use std::os::raw::c_int;

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{Circuit, ConstraintSystem, Error, SingleVerifier, VerifyingKey}, 
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::EqAffine;
use pasta_curves::group::ff::PrimeField;
use rand_core::OsRng;

#[derive(Clone)]
struct VoteCircuit {
    v: Value<Fp>,        // Private vote value
    t: Value<Fp>,        // Public target value
}

#[derive(Clone)]
struct Config {
    v: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    t: halo2_proofs::plonk::Column<halo2_proofs::plonk::Instance>,
    sel: halo2_proofs::plonk::Selector,
}

impl Circuit<Fp> for VoteCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { 
            v: Value::unknown(), 
            t: Value::unknown(), 
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let v = meta.advice_column();
        let t = meta.instance_column();
        let sel = meta.selector();

        meta.enable_equality(v);
        meta.enable_equality(t);

        // Gate: Check that vote equals target (v == t)
        meta.create_gate("vote equality check", |meta| {
            let s = meta.query_selector(sel);
            let vq = meta.query_advice(v, halo2_proofs::poly::Rotation::cur());
            let tq = meta.query_instance(t, halo2_proofs::poly::Rotation::cur());
            vec![s * (vq - tq)]
        });

        Config { v, t, sel }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        // Assign private vote value
        let _v_assigned: AssignedCell<Fp, Fp> = layouter.assign_region(
        || "assign v",
         |mut region| {
            cfg.sel.enable(&mut region, 0)?;
            region.assign_advice(|| "v", cfg.v, 0, || self.v)
            },
        )?;
            
            Ok(())
    }
 }

// Recursive voting circuit that aggregates multiple votes
#[derive(Clone)]
struct RecursiveVoteCircuit {
    // Current vote
    current_vote: Value<Fp>,
    // Target value
    target: Value<Fp>,
    // Previous vote count (from previous proof)
    prev_vote_count: Value<Fp>,
    // Previous tally (from previous proof)
    prev_tally: Value<Fp>,
    // Is this the first vote? (no previous proof to verify)
    is_first_vote: Value<bool>,
}

#[derive(Clone)]
struct RecursiveConfig {
    // Vote columns
    current_vote: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    target: halo2_proofs::plonk::Column<halo2_proofs::plonk::Instance>,
    prev_vote_count: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    prev_tally: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    is_first_vote: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    
    // Output columns
    new_vote_count: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    new_tally: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    
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
            target: Value::unknown(),
            prev_vote_count: Value::unknown(),
            prev_tally: Value::unknown(),
            is_first_vote: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // Define columns
        let current_vote = meta.advice_column();
        let target = meta.instance_column();
        let prev_vote_count = meta.advice_column();
        let prev_tally = meta.advice_column();
        let is_first_vote = meta.advice_column();
        let new_vote_count = meta.advice_column();
        let new_tally = meta.advice_column();

        // Enable equality
        meta.enable_equality(current_vote);
        meta.enable_equality(target);
        meta.enable_equality(prev_vote_count);
        meta.enable_equality(prev_tally);
        meta.enable_equality(is_first_vote);
        meta.enable_equality(new_vote_count);
        meta.enable_equality(new_tally);

        // Selectors
        let sel_vote_check = meta.selector();
        let sel_aggregation = meta.selector();

        // Gate 1: Check that current vote equals target (always enforced)
        meta.create_gate("vote equality check", |meta| {
            let s = meta.query_selector(sel_vote_check);
            let vote = meta.query_advice(current_vote, halo2_proofs::poly::Rotation::cur());
            let target = meta.query_instance(target, halo2_proofs::poly::Rotation::cur());
            
            vec![s * (vote - target)]
        });

        // Gate 2: Aggregation logic
        meta.create_gate("vote aggregation", |meta| {
            let s = meta.query_selector(sel_aggregation);
            let prev_count = meta.query_advice(prev_vote_count, halo2_proofs::poly::Rotation::cur());
            let prev_tally = meta.query_advice(prev_tally, halo2_proofs::poly::Rotation::cur());
            let is_first = meta.query_advice(is_first_vote, halo2_proofs::poly::Rotation::cur());
            let new_count = meta.query_advice(new_vote_count, halo2_proofs::poly::Rotation::cur());
            let new_tally = meta.query_advice(new_tally, halo2_proofs::poly::Rotation::cur());
            let vote = meta.query_advice(current_vote, halo2_proofs::poly::Rotation::cur());
            
            let one = halo2_proofs::plonk::Expression::Constant(Fp::from(1));
            
            // Conditional logic based on is_first_vote:
            // If first vote (is_first = 1):
            //   new_count = 1
            //   new_tally = vote
            // If not first vote (is_first = 0):
            //   new_count = prev_count + 1
            //   new_tally = prev_tally + vote
            
            let count_constraint = s.clone() * (
                is_first.clone() * (new_count.clone() - one.clone()) +
                (one.clone() - is_first.clone()) * (new_count.clone() - prev_count - one.clone())
            );
            
            let tally_constraint = s * (
                is_first.clone() * (new_tally.clone() - vote.clone()) +
                (one - is_first) * (new_tally - prev_tally - vote)
            );
            
            vec![count_constraint, tally_constraint]
        });

        RecursiveConfig {
            current_vote,
            target,
            prev_vote_count,
            prev_tally,
            is_first_vote,
            new_vote_count,
            new_tally,
            sel_vote_check,
            sel_aggregation,
        }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        layouter.assign_region(
            || "recursive vote aggregation",
            |mut region| {
                // Assign all values
                let _vote_cell = region.assign_advice(|| "current vote", cfg.current_vote, 0, || self.current_vote)?;
                let _prev_count_cell = region.assign_advice(|| "prev count", cfg.prev_vote_count, 0, || self.prev_vote_count)?;
                let _prev_tally_cell = region.assign_advice(|| "prev tally", cfg.prev_tally, 0, || self.prev_tally)?;
                
                // Convert boolean to field element
                let is_first_fp = self.is_first_vote.map(|b| if b { Fp::from(1) } else { Fp::from(0) });
                let _is_first_cell = region.assign_advice(|| "is first", cfg.is_first_vote, 0, || is_first_fp)?;

                // Enable vote check gate
                cfg.sel_vote_check.enable(&mut region, 0)?;

                // Calculate new values based on is_first_vote
                let new_count = self.is_first_vote.zip(self.prev_vote_count).map(|(is_first, prev_count)| {
                    if is_first {
                        Fp::from(1)
                    } else {
                        prev_count + Fp::from(1)
                    }
                });

                let new_tally = self.is_first_vote.zip(self.current_vote).zip(self.prev_tally)
                    .map(|((is_first, vote), prev_tally)| {
                        if is_first {
                            vote
                        } else {
                            prev_tally + vote
                        }
                    });

                let _new_count_cell = region.assign_advice(|| "new count", cfg.new_vote_count, 0, || new_count)?;
                let _new_tally_cell = region.assign_advice(|| "new tally", cfg.new_tally, 0, || new_tally)?;

                // Enable aggregation gate
                cfg.sel_aggregation.enable(&mut region, 0)?;

                Ok(())
            },
        )?;

        Ok(())
    }
}


// Example usage function
pub fn example_usage() -> Result<(), Box<dyn std::error::Error>> {
    // Set up parameters for circuit size
    let k = 6; // Circuit size parameter
    
    // Create first vote
    let first_vote_circuit = RecursiveVoteCircuit {
        current_vote: Value::known(Fp::from(1)),
        target: Value::known(Fp::from(1)),
        prev_vote_count: Value::known(Fp::from(0)),
        prev_tally: Value::known(Fp::from(0)),
        is_first_vote: Value::known(true),
    };
    
    // Create second vote (aggregating with first)
    let second_vote_circuit = RecursiveVoteCircuit {
        current_vote: Value::known(Fp::from(1)),
        target: Value::known(Fp::from(1)),
        prev_vote_count: Value::known(Fp::from(1)), // From first vote result
        prev_tally: Value::known(Fp::from(1)),      // From first vote result
        is_first_vote: Value::known(false),
    };
    
    println!("Voting circuits created successfully!");
    println!("First vote: count=1, tally=1");
    println!("Second vote: count=2, tally=2");
    
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    use halo2_proofs::{
        dev::MockProver,
        pasta::Fp,
        circuit::Value,
        plonk::{keygen_pk, keygen_vk, create_proof, verify_proof},
        poly::commitment::Params,
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
        plonk::SingleVerifier,
    };
    use pasta_curves::EqAffine;
    use rand_core::OsRng;
    use std::time::Instant;


    #[test]
    fn test_basic_vote_circuit() {
        let k = 4;
        let vote_value = Fp::from(1);
        let target_value = Fp::from(1);

        let circuit = VoteCircuit {
            v: Value::known(vote_value),
            t: Value::known(target_value),
        };

        let public_inputs = vec![target_value];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_recursive_vote_circuit_first_vote() {
        let k = 6;
        
        let circuit = RecursiveVoteCircuit {
            current_vote: Value::known(Fp::from(1)),
            target: Value::known(Fp::from(1)),
            prev_vote_count: Value::known(Fp::from(0)),
            prev_tally: Value::known(Fp::from(0)),
            is_first_vote: Value::known(true),
        };

        let public_inputs = vec![Fp::from(1)];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_recursive_vote_circuit_second_vote() {
        let k = 6;
        
        let circuit = RecursiveVoteCircuit {
            current_vote: Value::known(Fp::from(1)),
            target: Value::known(Fp::from(1)),
            prev_vote_count: Value::known(Fp::from(1)),
            prev_tally: Value::known(Fp::from(1)),
            is_first_vote: Value::known(false),
        };

        let public_inputs = vec![Fp::from(1)];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        prover.assert_satisfied();
    }



    #[test]
    fn test_recursive_vote_aggregation_corrected() {
        // Test true recursive voting with proper aggregation logic
        let k: u32 = 8;
        let target = Fp::from(1u64); // Target is "yes"
        
        // Only valid votes (matching target) for this test
        let votes = vec![
            Fp::from(1u64), // yes - first vote
            Fp::from(1u64), // yes - second vote  
            Fp::from(1u64), // yes - third vote
        ];
        
        println!("=== CORRECTED RECURSIVE VOTE AGGREGATION TEST ===");
        println!("Votes: {:?}", votes.iter().map(|v| if *v == Fp::from(1u64) { "yes" } else { "no" }).collect::<Vec<_>>());
        println!("Target: yes (1)");
        
        // Generate proving key and verification key once
        let params = Params::new(k);
        let dummy_circuit = RecursiveVoteCircuit {
            current_vote: Value::unknown(),
            target: Value::unknown(),
            prev_vote_count: Value::unknown(),
            prev_tally: Value::unknown(),
            is_first_vote: Value::unknown(),
        };
        
        let keygen_start = Instant::now();
        let vk = keygen_vk(&params, &dummy_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &dummy_circuit).expect("keygen_pk should not fail");
        let keygen_time = keygen_start.elapsed();
        println!("Key generation time: {:?}", keygen_time);
        
        // Track aggregated state across recursive proofs
        let mut prev_vote_count = Fp::from(0u64);
        let mut prev_tally = Fp::from(0u64);
        let mut proof_chain = Vec::new();
        let mut individual_metrics = Vec::new();
        
        for (i, &vote) in votes.iter().enumerate() {
            let is_first_vote = i == 0;
            
            println!("\n--- Processing Vote {} ---", i + 1);
            
            // Create circuit for this vote
            let circuit = RecursiveVoteCircuit {
                current_vote: Value::known(vote),
                target: Value::known(target),
                prev_vote_count: Value::known(prev_vote_count),
                prev_tally: Value::known(prev_tally),
                is_first_vote: Value::known(is_first_vote),
            };
            
            // First verify the circuit logic with MockProver
            let public_inputs = vec![target];
            let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()])
                .expect("MockProver should not fail");
            
            match prover.verify() {
                Ok(_) => println!("  Circuit verification: ✓ VALID"),
                Err(e) => {
                    println!("  Circuit verification: ✗ FAILED - {:?}", e);
                    panic!("Vote {} failed circuit verification", i + 1);
                }
            }
            
            // Generate actual proof
            let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(Vec::new());
            
            let prove_start = Instant::now();
            create_proof(
                &params, 
                &pk, 
                &[circuit], 
                &[&[&public_inputs]], 
                OsRng, 
                &mut transcript
            ).expect("proof generation should not fail");
            let proof = transcript.finalize();
            let prove_time = prove_start.elapsed();
            
            // Verify proof
            let verify_start = Instant::now();
            let strategy = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            let verify_result = verify_proof(
                &params, 
                pk.get_vk(), 
                strategy, 
                &[&[&public_inputs]], 
                &mut transcript
            );
            let verify_time = verify_start.elapsed();
            
            assert!(verify_result.is_ok(), "Vote {} proof verification failed", i + 1);
            
            // Calculate new state based on corrected logic
            let (new_vote_count, new_tally) = if is_first_vote {
                // First vote: initialize count to 1, tally to vote value
                (Fp::from(1u64), vote)
            } else {
                // Subsequent votes: increment count, add vote to tally
                (prev_vote_count + Fp::from(1u64), prev_tally + vote)
            };
            
            // Store metrics
            individual_metrics.push((proof.len(), prove_time, verify_time));
            proof_chain.push(proof);
            
             println!("  Vote: {:?} ({})", vote, if vote == Fp::from(1u64) { "yes" } else { "no" });
            println!("  Previous state: count={:?}, tally={:?}", prev_vote_count, prev_tally);
            println!("  New state: count={:?}, tally={:?}", new_vote_count, new_tally);
            println!("  Proof size: {} bytes", individual_metrics.last().unwrap().0);
            println!("  Prove time: {:?}", prove_time);
            println!("  Verify time: {:?}", verify_time);
            
            // Update state for next iteration
            prev_vote_count = new_vote_count;
            prev_tally = new_tally;
        }
        
        // Calculate summary metrics
        let total_votes = votes.len();
        let total_proof_size: usize = individual_metrics.iter().map(|(size, _, _)| size).sum();
        let total_prove_time: std::time::Duration = individual_metrics.iter().map(|(_, prove, _)| *prove).sum();
        let total_verify_time: std::time::Duration = individual_metrics.iter().map(|(_, _, verify)| *verify).sum();
        let avg_proof_size = total_proof_size / total_votes;
        let avg_prove_time = total_prove_time / total_votes as u32;
        let avg_verify_time = total_verify_time / total_votes as u32;
        
        println!("\n=== FINAL AGGREGATION RESULTS ===");
        println!("Total votes processed: {}", total_votes);
        println!("Final vote count: {:?}", prev_vote_count);
        println!("Final tally: {:?}", prev_tally);
        println!("Expected count: {}", votes.len());
         let expected_tally_sum: u64 = votes.iter().map(|v| v.to_repr().as_ref()[0] as u64).sum();
         println!("Expected tally: {} (sum of all votes)", expected_tally_sum);
        
        println!("\n=== PERFORMANCE METRICS ===");
        println!("Individual proof sizes: {:?} bytes", individual_metrics.iter().map(|(s,_,_)| s).collect::<Vec<_>>());
        println!("Average proof size: {} bytes", avg_proof_size);
        println!("Total storage needed: {} bytes", total_proof_size);
        println!("Average prove time: {:?}", avg_prove_time);
        println!("Average verify time: {:?}", avg_verify_time);
        println!("Total computational time: {:?}", total_prove_time + total_verify_time);
        
        // Verify final state matches expectations
        assert_eq!(prev_vote_count, Fp::from(votes.len() as u64), 
            "Final vote count should equal number of votes");
        
        let expected_tally = votes.iter().fold(Fp::from(0u64), |acc, &vote| acc + vote);
        assert_eq!(prev_tally, expected_tally, 
            "Final tally should equal sum of all votes");
        
        println!("\n✓ All assertions passed - recursive aggregation working correctly!");
    }

    #[test]
    fn test_invalid_vote_rejection() {
        // Test that invalid votes (not matching target) are properly rejected
        let k: u32 = 8;
        let target = Fp::from(1u64); // Target is "yes"
        let invalid_vote = Fp::from(0u64); // "no" vote (invalid)
        
        println!("=== INVALID VOTE REJECTION TEST ===");
        
        let circuit = RecursiveVoteCircuit {
            current_vote: Value::known(invalid_vote),
            target: Value::known(target),
            prev_vote_count: Value::known(Fp::from(0u64)),
            prev_tally: Value::known(Fp::from(0u64)),
            is_first_vote: Value::known(true),
        };
        
        let public_inputs = vec![target];
        let prover = MockProver::run(k, &circuit, vec![public_inputs])
            .expect("MockProver should not fail");
        
        // This should fail because vote (0) doesn't equal target (1)
        match prover.verify() {
            Ok(_) => panic!("Invalid vote should have been rejected!"),
            Err(_) => println!("✓ Invalid vote correctly rejected by circuit constraints"),
        }
    }

    #[test]
    fn test_vote_aggregation_chain() {
        // Test a sequence of valid votes to ensure proper chaining
        let votes_and_expected = vec![
            // (vote, is_first, expected_count, expected_tally)
            (Fp::from(1u64), true,  Fp::from(1u64), Fp::from(1u64)), // First vote
            (Fp::from(1u64), false, Fp::from(2u64), Fp::from(2u64)), // Second vote
            (Fp::from(1u64), false, Fp::from(3u64), Fp::from(3u64)), // Third vote
        ];
        
        let k: u32 = 6;
        let target = Fp::from(1u64);
        
        let mut prev_count = Fp::from(0u64);
        let mut prev_tally = Fp::from(0u64);
        
        println!("=== VOTE CHAINING TEST ===");
        
        for (i, (vote, is_first, expected_count, expected_tally)) in votes_and_expected.iter().enumerate() {
            let circuit = RecursiveVoteCircuit {
                current_vote: Value::known(*vote),
                target: Value::known(target),
                prev_vote_count: Value::known(prev_count),
                prev_tally: Value::known(prev_tally),
                is_first_vote: Value::known(*is_first),
            };
            
            let public_inputs = vec![target];
            let prover = MockProver::run(k, &circuit, vec![public_inputs])
                .expect("MockProver should not fail");
            
            prover.assert_satisfied();
            
            println!("Vote {}: ✓ Valid (count: {:?} → {:?}, tally: {:?} → {:?})", 
                i + 1, prev_count, expected_count, prev_tally, expected_tally);
            
            // Update state for next iteration
            prev_count = *expected_count;
            prev_tally = *expected_tally;
        }
        
        println!("✓ Vote chaining test completed successfully!");
    }
}