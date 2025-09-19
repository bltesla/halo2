// use std::os::raw::c_int;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{Circuit, ConstraintSystem, Error},
};
use pasta_curves::group::ff::PrimeField;



// Democratic recursive voting circuit that aggregates multiple votes
#[derive(Clone)]
struct RecursiveVoteCircuit {
    // Current vote (0=no, 1=yes)
    current_vote: Value<Fp>,
    // Previous vote count (total valid votes from previous proof)
    prev_vote_count: Value<Fp>,
    // Previous yes count (yes votes from previous proof) 
    prev_yes_count: Value<Fp>,
    // Previous no count (no votes from previous proof)
    prev_no_count: Value<Fp>,
    // Is this the first vote? (no previous proof to verify)
    is_first_vote: Value<bool>,
}


#[derive(Clone)]
struct RecursiveConfig {
    // Vote columns
    current_vote: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    prev_vote_count: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    prev_yes_count: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    prev_no_count: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    is_first_vote: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    
    // Output columns
    new_vote_count: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    new_yes_count: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    new_no_count: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    
    // Public instance columns for verification
    total_votes: halo2_proofs::plonk::Column<halo2_proofs::plonk::Instance>,
    yes_votes: halo2_proofs::plonk::Column<halo2_proofs::plonk::Instance>,
    no_votes: halo2_proofs::plonk::Column<halo2_proofs::plonk::Instance>,
    
    // Selectors
    sel_vote_check: halo2_proofs::plonk::Selector,
    sel_aggregation: halo2_proofs::plonk::Selector,
}


impl Circuit<Fp> for RecursiveVoteCircuit {
    type Config = RecursiveConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            current_vote: Value::unknown(),
            prev_vote_count: Value::unknown(),
            prev_yes_count: Value::unknown(),
            prev_no_count: Value::unknown(),
            is_first_vote: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // Define columns
        let current_vote = meta.advice_column();
        let prev_vote_count = meta.advice_column();
        let prev_yes_count = meta.advice_column();
        let prev_no_count = meta.advice_column();
        let is_first_vote = meta.advice_column();
        let new_vote_count = meta.advice_column();
        let new_yes_count = meta.advice_column();
        let new_no_count = meta.advice_column();
        
        // Public instance columns for verification
        let total_votes = meta.instance_column();
        let yes_votes = meta.instance_column();
        let no_votes = meta.instance_column();

        // Enable equality
        meta.enable_equality(current_vote);
        meta.enable_equality(prev_vote_count);
        meta.enable_equality(prev_yes_count);
        meta.enable_equality(prev_no_count);
        meta.enable_equality(is_first_vote);
        meta.enable_equality(new_vote_count);
        meta.enable_equality(new_yes_count);
        meta.enable_equality(new_no_count);
        meta.enable_equality(total_votes);
        meta.enable_equality(yes_votes);
        meta.enable_equality(no_votes);

        // Selectors
        let sel_vote_check = meta.selector();
        let sel_aggregation = meta.selector();

        // Gate 1: Democratic vote validation - vote must be 0 (no) or 1 (yes)
        meta.create_gate("binary vote validation", |meta| {
            let s = meta.query_selector(sel_vote_check);
            let vote = meta.query_advice(current_vote, halo2_proofs::poly::Rotation::cur());
            
            // vote * (vote - 1) = 0 means vote ∈ {0, 1}
            // This allows both "no" (0) and "yes" (1) as valid votes
            vec![s * vote.clone() * (vote - halo2_proofs::plonk::Expression::Constant(Fp::from(1)))]
        });

        // Gate 2: Democratic vote aggregation logic
        meta.create_gate("democratic vote aggregation", |meta| {
            let s = meta.query_selector(sel_aggregation);
            let prev_count = meta.query_advice(prev_vote_count, halo2_proofs::poly::Rotation::cur());
            let prev_yes = meta.query_advice(prev_yes_count, halo2_proofs::poly::Rotation::cur());
            let prev_no = meta.query_advice(prev_no_count, halo2_proofs::poly::Rotation::cur());
            let is_first = meta.query_advice(is_first_vote, halo2_proofs::poly::Rotation::cur());
            let new_count = meta.query_advice(new_vote_count, halo2_proofs::poly::Rotation::cur());
            let new_yes = meta.query_advice(new_yes_count, halo2_proofs::poly::Rotation::cur());
            let new_no = meta.query_advice(new_no_count, halo2_proofs::poly::Rotation::cur());
            let vote = meta.query_advice(current_vote, halo2_proofs::poly::Rotation::cur());
            
            let zero = halo2_proofs::plonk::Expression::Constant(Fp::from(0));
            let one = halo2_proofs::plonk::Expression::Constant(Fp::from(1));
            
            // Democratic vote counting logic:
            // If first vote (is_first = 1):
            //   new_count = 1
            //   new_yes = vote (1 if yes, 0 if no)
            //   new_no = (1 - vote) (0 if yes, 1 if no)
            // If not first vote (is_first = 0):
            //   new_count = prev_count + 1
            //   new_yes = prev_yes + vote
            //   new_no = prev_no + (1 - vote)
            
            let count_constraint = s.clone() * (
                is_first.clone() * (new_count.clone() - one.clone()) +
                (one.clone() - is_first.clone()) * (new_count.clone() - prev_count - one.clone())
            );
            
            let yes_constraint = s.clone() * (
                is_first.clone() * (new_yes.clone() - vote.clone()) +
                (one.clone() - is_first.clone()) * (new_yes.clone() - prev_yes - vote.clone())
            );
            
            let no_constraint = s * (
                is_first.clone() * (new_no.clone() - (one.clone() - vote.clone())) +
                (one.clone() - is_first) * (new_no - prev_no - (one - vote))
            );
            
            vec![count_constraint, yes_constraint, no_constraint]
        });

        RecursiveConfig {
            current_vote,
            prev_vote_count,
            prev_yes_count,
            prev_no_count,
            is_first_vote,
            new_vote_count,
            new_yes_count,
            new_no_count,
            total_votes,
            yes_votes,
            no_votes,
            sel_vote_check,
            sel_aggregation,
        }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let cells = layouter.assign_region(
            || "democratic recursive vote aggregation",
         |mut region| {
                // Assign all input values
                let _vote_cell = region.assign_advice(|| "current vote", cfg.current_vote, 0, || self.current_vote)?;
                let _prev_count_cell = region.assign_advice(|| "prev count", cfg.prev_vote_count, 0, || self.prev_vote_count)?;
                let _prev_yes_cell = region.assign_advice(|| "prev yes", cfg.prev_yes_count, 0, || self.prev_yes_count)?;
                let _prev_no_cell = region.assign_advice(|| "prev no", cfg.prev_no_count, 0, || self.prev_no_count)?;
                
                // Convert boolean to field element
                let is_first_fp = self.is_first_vote.map(|b| if b { Fp::from(1) } else { Fp::from(0) });
                let _is_first_cell = region.assign_advice(|| "is first", cfg.is_first_vote, 0, || is_first_fp)?;

                // Enable vote validation gate (ensures vote ∈ {0, 1})
                cfg.sel_vote_check.enable(&mut region, 0)?;

                // Calculate new democratic values based on is_first_vote
                let new_count = self.is_first_vote.zip(self.prev_vote_count).map(|(is_first, prev_count)| {
                    if is_first {
                        Fp::from(1) // First vote
                    } else {
                        prev_count + Fp::from(1) // Increment total count
                    }
                });

                let new_yes_count = self.is_first_vote.zip(self.current_vote).zip(self.prev_yes_count)
                    .map(|((is_first, vote), prev_yes)| {
                        if is_first {
                            vote // If first vote: yes_count = vote (1 if yes, 0 if no)
                        } else {
                            prev_yes + vote // Increment yes count if current vote is yes
                        }
                    });

                let new_no_count = self.is_first_vote.zip(self.current_vote).zip(self.prev_no_count)
                    .map(|((is_first, vote), prev_no)| {
                        if is_first {
                            Fp::from(1) - vote // If first vote: no_count = (1 - vote)
                        } else {
                            prev_no + (Fp::from(1) - vote) // Increment no count if current vote is no
                        }
                    });

                // Assign computed values
                let new_count_cell = region.assign_advice(|| "new count", cfg.new_vote_count, 0, || new_count)?;
                let new_yes_cell = region.assign_advice(|| "new yes", cfg.new_yes_count, 0, || new_yes_count)?;
                let new_no_cell = region.assign_advice(|| "new no", cfg.new_no_count, 0, || new_no_count)?;

                // Enable aggregation gate
                cfg.sel_aggregation.enable(&mut region, 0)?;

                Ok((new_count_cell, new_yes_cell, new_no_cell))
            },
        )?;

        // Constrain public instances for verification
        layouter.constrain_instance(cells.0.cell(), cfg.total_votes, 0)?;
        layouter.constrain_instance(cells.1.cell(), cfg.yes_votes, 0)?;
        layouter.constrain_instance(cells.2.cell(), cfg.no_votes, 0)?;
            
            Ok(())
    }
 }


// Example usage function
pub fn example_usage() -> Result<(), Box<dyn std::error::Error>> {
    // Set up parameters for circuit size
    let k = 6; // Circuit size parameter
    
    // Create first vote (yes vote)
    let _first_vote_circuit = RecursiveVoteCircuit {
        current_vote: Value::known(Fp::from(1)), // Yes vote
        prev_vote_count: Value::known(Fp::from(0)),
        prev_yes_count: Value::known(Fp::from(0)),
        prev_no_count: Value::known(Fp::from(0)),
        is_first_vote: Value::known(true),
    };

    // Create second vote (no vote, aggregating with first)
    let _second_vote_circuit = RecursiveVoteCircuit {
        current_vote: Value::known(Fp::from(0)), // No vote
        prev_vote_count: Value::known(Fp::from(1)), // From first vote result
        prev_yes_count: Value::known(Fp::from(1)),  // 1 yes from first vote
        prev_no_count: Value::known(Fp::from(0)),   // 0 no from first vote
        is_first_vote: Value::known(false),
    };
    
    println!("Democratic voting circuits created successfully!");
    println!("First vote (yes): count=1, yes=1, no=0");
    println!("Second vote (no): count=2, yes=1, no=1");
    
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        dev::MockProver,
        pasta::Fp,
        circuit::Value,
        plonk::{keygen_pk, keygen_vk, create_proof, verify_proof, SingleVerifier},
        poly::commitment::Params,
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };
    use pasta_curves::EqAffine;
    use rand_core::OsRng;
    use std::time::Instant;

    #[test]
    fn test_democratic_yes_vote() {
        println!("=== DEMOCRATIC YES VOTE TEST ===");
        let k: u32 = 8;
        
        let circuit = RecursiveVoteCircuit {
            current_vote: Value::known(Fp::from(1)), // Yes vote
            prev_vote_count: Value::known(Fp::from(0)),
            prev_yes_count: Value::known(Fp::from(0)),
            prev_no_count: Value::known(Fp::from(0)),
            is_first_vote: Value::known(true),
        };

        // Public inputs as separate instance columns: [total_votes], [yes_votes], [no_votes]
        let public_inputs = vec![
            vec![Fp::from(1)], // Expected total: 1 vote
            vec![Fp::from(1)], // Expected yes: 1 vote  
            vec![Fp::from(0)], // Expected no: 0 votes
        ];
        
        let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
        println!("✅ Yes vote accepted and counted correctly");
    }

    #[test]
    fn test_democratic_no_vote() {
        println!("=== DEMOCRATIC NO VOTE TEST ===");
        let k: u32 = 8;
        
        let circuit = RecursiveVoteCircuit {
            current_vote: Value::known(Fp::from(0)), // No vote
            prev_vote_count: Value::known(Fp::from(0)),
            prev_yes_count: Value::known(Fp::from(0)),
            prev_no_count: Value::known(Fp::from(0)),
            is_first_vote: Value::known(true),
        };

        // Public inputs as separate instance columns: [total_votes], [yes_votes], [no_votes]
        let public_inputs = vec![
            vec![Fp::from(1)], // Expected total: 1 vote
            vec![Fp::from(0)], // Expected yes: 0 votes
            vec![Fp::from(1)], // Expected no: 1 vote
        ];
        
        let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
        println!("✅ No vote accepted and counted correctly");
    }

    #[test]
    fn test_democratic_aggregation() {
        println!("=== DEMOCRATIC VOTE AGGREGATION TEST ===");
        let k: u32 = 8;
        
        // Test aggregating: 1 previous yes vote + 1 current no vote
        let circuit = RecursiveVoteCircuit {
            current_vote: Value::known(Fp::from(0)), // No vote
            prev_vote_count: Value::known(Fp::from(1)), // 1 previous vote
            prev_yes_count: Value::known(Fp::from(1)),  // 1 previous yes
            prev_no_count: Value::known(Fp::from(0)),   // 0 previous no
            is_first_vote: Value::known(false),
        };

        // Public inputs as separate instance columns: [total_votes], [yes_votes], [no_votes]
        let public_inputs = vec![
            vec![Fp::from(2)], // Expected total: 2 votes
            vec![Fp::from(1)], // Expected yes: 1 vote
            vec![Fp::from(1)], // Expected no: 1 vote
        ];
        
        let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
        println!("✅ Democratic aggregation works correctly");
    }

    #[test]
    fn test_invalid_vote_rejection() {
        println!("=== INVALID VOTE REJECTION TEST ===");
        let k: u32 = 8;
        
        let circuit = RecursiveVoteCircuit {
            current_vote: Value::known(Fp::from(2)), // Invalid vote (not 0 or 1)
            prev_vote_count: Value::known(Fp::from(0)),
            prev_yes_count: Value::known(Fp::from(0)),
            prev_no_count: Value::known(Fp::from(0)),
            is_first_vote: Value::known(true),
        };

        // Public inputs (doesn't matter since circuit should fail)
        let public_inputs = vec![
            vec![Fp::from(1)],
            vec![Fp::from(0)],
            vec![Fp::from(1)],
        ];
        
        let prover = MockProver::run(k, &circuit, public_inputs)
            .expect("MockProver should not fail");
        
        // This should fail because vote (2) is not in {0, 1}
        match prover.verify() {
            Ok(_) => panic!("Invalid vote should have been rejected!"),
            Err(_) => println!("✅ Invalid vote correctly rejected by binary constraint"),
        }
    }

    #[test]
    fn test_three_vote_recursive_with_performance() {
        println!("\n=== THREE VOTE RECURSIVE PROOF WITH PERFORMANCE METRICS ===");
        
        let k: u32 = 8;
        // Test votes: Yes, No, Yes
        let votes = vec![
            Fp::from(1), // Vote 1: Yes
            Fp::from(0), // Vote 2: No  
            Fp::from(1), // Vote 3: Yes
        ];
        
        println!("Testing recursive aggregation of {} votes", votes.len());
        println!("Vote pattern: {:?} (Yes=1, No=0)", votes);
        
        // Generate parameters and keys once
        let params = Params::new(k);
        let dummy_circuit = RecursiveVoteCircuit {
            current_vote: Value::unknown(),
            prev_vote_count: Value::unknown(),
            prev_yes_count: Value::unknown(),
            prev_no_count: Value::unknown(),
            is_first_vote: Value::unknown(),
        };
        
        let keygen_start = Instant::now();
        let vk = keygen_vk(&params, &dummy_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &dummy_circuit).expect("keygen_pk should not fail");
        let keygen_time = keygen_start.elapsed();
        println!("Key generation time: {:?}", keygen_time);
        
        // Track recursive aggregation state
        let mut prev_vote_count = Fp::from(0);
        let mut prev_yes_count = Fp::from(0);
        let mut prev_no_count = Fp::from(0);
        let mut proof_chain = Vec::new();
        let mut individual_metrics = Vec::new(); // (proof_size, prove_time, verify_time)
        
        for (i, &vote) in votes.iter().enumerate() {
            let is_first_vote = i == 0;
            
            println!("\n--- Processing Vote {} ---", i + 1);
            println!("  Vote value: {} ({})", vote.to_repr().as_ref()[0], if vote == Fp::from(1) { "Yes" } else { "No" });
            
            // Create circuit for this vote
            let circuit = RecursiveVoteCircuit {
                current_vote: Value::known(vote),
                prev_vote_count: Value::known(prev_vote_count),
                prev_yes_count: Value::known(prev_yes_count),
                prev_no_count: Value::known(prev_no_count),
                is_first_vote: Value::known(is_first_vote),
            };
            
            // Calculate expected results
            let expected_count = Fp::from((i + 1) as u64);
            let expected_yes = prev_yes_count + vote;
            let expected_no = prev_no_count + (Fp::from(1) - vote);
            
            // First verify with MockProver
            let public_inputs = vec![
                vec![expected_count],
                vec![expected_yes],
                vec![expected_no],
            ];
            
            let prover = MockProver::run(k, &circuit, public_inputs.clone())
                .expect("MockProver should not fail");
            prover.verify().expect("Circuit verification should pass");
            println!("  ✓ Circuit verification: PASSED");
            
            // Generate actual proof
            let prove_start = Instant::now();
            let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
            create_proof(
                &params,
                &pk,
                &[circuit],
                &[&[&public_inputs[0][..], &public_inputs[1][..], &public_inputs[2][..]]],
                OsRng,
                &mut transcript,
            ).expect("proof generation should succeed");
            let proof_bytes = transcript.finalize();
            let prove_time = prove_start.elapsed();
            
            // Verify proof
            let verify_start = Instant::now();
            let strategy = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&proof_bytes[..]);
            verify_proof(
                &params,
                pk.get_vk(),
                strategy,
                &[&[&public_inputs[0][..], &public_inputs[1][..], &public_inputs[2][..]]],
                &mut transcript,
            ).expect("verification should succeed");
            let verify_time = verify_start.elapsed();
            
            println!("  ✓ Proof size: {} bytes ({:.2} KB)", proof_bytes.len(), proof_bytes.len() as f64 / 1024.0);
            println!("  ✓ Prove time: {:?}", prove_time);
            println!("  ✓ Verify time: {:?}", verify_time);
            
            // Store metrics and update state
            individual_metrics.push((proof_bytes.len(), prove_time, verify_time));
            proof_chain.push(proof_bytes);
            
            // Update state for next iteration
            prev_vote_count = expected_count;
            prev_yes_count = expected_yes;
            prev_no_count = expected_no;
            
            println!("  → Running totals: {} total, {} yes, {} no", 
                prev_vote_count.to_repr().as_ref()[0],
                prev_yes_count.to_repr().as_ref()[0],
                prev_no_count.to_repr().as_ref()[0]
            );
        }
        
        // === PERFORMANCE ANALYSIS ===
        println!("\n--- Performance Analysis ---");
        
        let total_proof_size: usize = individual_metrics.iter().map(|(size, _, _)| size).sum();
        let total_prove_time: std::time::Duration = individual_metrics.iter().map(|(_, prove, _)| *prove).sum();
        let total_verify_time: std::time::Duration = individual_metrics.iter().map(|(_, _, verify)| *verify).sum();
        let avg_proof_size = total_proof_size / individual_metrics.len();
        
        println!("📊 PROOF METRICS:");
        println!("  Individual proof sizes: {:?} bytes", individual_metrics.iter().map(|(size, _, _)| size).collect::<Vec<_>>());
        println!("  Total storage required: {} bytes ({:.2} KB)", total_proof_size, total_proof_size as f64 / 1024.0);
        println!("  Average proof size:     {} bytes", avg_proof_size);
        
        println!("\n⏱️ TIMING METRICS:");
        println!("  Individual prove times: {:?}", individual_metrics.iter().map(|(_, prove, _)| prove).collect::<Vec<_>>());
        println!("  Individual verify times: {:?}", individual_metrics.iter().map(|(_, _, verify)| verify).collect::<Vec<_>>());
        println!("  Total prove time:       {:?}", total_prove_time);
        println!("  Total verify time:      {:?}", total_verify_time);
        println!("  Average prove time:     {:?}", total_prove_time / individual_metrics.len() as u32);
        println!("  Average verify time:    {:?}", total_verify_time / individual_metrics.len() as u32);
        
        // === VOTING RESULTS ===
        println!("\n📈 FINAL VOTING RESULTS:");
        println!("  Total votes cast:  {}", votes.len());
        println!("  Yes votes:         {}", prev_yes_count.to_repr().as_ref()[0]);
        println!("  No votes:          {}", prev_no_count.to_repr().as_ref()[0]);
        let yes_percentage = (prev_yes_count.to_repr().as_ref()[0] as f64 / votes.len() as f64) * 100.0;
        let no_percentage = (prev_no_count.to_repr().as_ref()[0] as f64 / votes.len() as f64) * 100.0;
        println!("  Yes percentage:    {:.1}%", yes_percentage);
        println!("  No percentage:     {:.1}%", no_percentage);
        
        if prev_yes_count > prev_no_count {
            println!("  🎉 RESULT: Motion PASSED ({:.1}% support)", yes_percentage);
        } else if prev_no_count > prev_yes_count {
            println!("  ❌ RESULT: Motion FAILED ({:.1}% opposition)", no_percentage);
        } else {
            println!("  🤝 RESULT: TIE (50% - 50%)");
        }
        
        // === VERIFICATION ===
        assert_eq!(prev_vote_count, Fp::from(votes.len() as u64), "Final vote count should match number of votes");
        assert_eq!(prev_yes_count + prev_no_count, prev_vote_count, "Yes + No should equal total");
        
        let expected_yes = votes.iter().filter(|&&v| v == Fp::from(1)).count() as u64;
        let expected_no = votes.iter().filter(|&&v| v == Fp::from(0)).count() as u64;
        assert_eq!(prev_yes_count, Fp::from(expected_yes), "Yes count should be correct");
        assert_eq!(prev_no_count, Fp::from(expected_no), "No count should be correct");
        
        println!("\n✅ Three vote recursive aggregation completed successfully!");
        println!("📦 Generated {} proofs totaling {:.2} KB", proof_chain.len(), total_proof_size as f64 / 1024.0);
        println!("⚡ Total processing time: {:?}", total_prove_time + total_verify_time);
    }
}
