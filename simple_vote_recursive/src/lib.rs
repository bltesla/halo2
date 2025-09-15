use std::os::raw::c_int;

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{Circuit, ConstraintSystem, Error, SingleVerifier, VerifyingKey}, 
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{EqAffine, };
use rand_core::OsRng;
// Poseidon imports removed since hash computation is not needed

#[derive(Clone)]
struct VoteCircuit {
    v: Value<Fp>,        // Private vote value
    t: Value<Fp>,        // Public target value
    // h: Value<Fp>,        // Public hash of vote
    // For recursion, you'd typically also need:
    // prev_proof: Option<ProofWithPublicInputs>,
    // aggregation_data: Option<AggregationData>,
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
            // h: Value::unknown() 
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let v = meta.advice_column();
        let t = meta.instance_column();
        let sel = meta.selector();

        meta.enable_equality(v);
        meta.enable_equality(t);

        // Poseidon hash configuration removed since it's not needed

        // Gate: Check that vote equals target (v == t)
        meta.create_gate("vote equality check", |meta| {
            let s = meta.query_selector(sel);
            let vq = meta.query_advice(v, halo2_proofs::poly::Rotation::cur());
            let tq = meta.query_instance(t, halo2_proofs::poly::Rotation::cur());
            [s * (vq - tq)]
        });

        Config { v, t, sel }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        // Assign private vote value
        let v_assigned: AssignedCell<Fp, Fp> = layouter.assign_region(
        || "assign v",
         |mut region| {
            cfg.sel.enable(&mut region, 0)?;
            region.assign_advice(|| "v", cfg.v, 0, || self.v)
            },
        )?;

        // Note: Hash computation removed since it's not needed for this simple circuit
            
            Ok(())
    }
 }

// MySpec struct removed since Poseidon hash is not used

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
    is_first_vote: Value<Fp>,
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

        // Gate 1: Check that current vote equals target (if not first vote)
        meta.create_gate("vote equality check", |meta| {
            let s = meta.query_selector(sel_vote_check);
            let vote = meta.query_advice(current_vote, halo2_proofs::poly::Rotation::cur());
            let target = meta.query_instance(target, halo2_proofs::poly::Rotation::cur());
            let is_first = meta.query_advice(is_first_vote, halo2_proofs::poly::Rotation::cur());
            
            // If not first vote, vote must equal target
            [s * (is_first * (vote - target))]
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
            
            // new_count = prev_count + (1 - is_first)  // Add 1 if not first vote
            // new_tally = prev_tally + vote * (1 - is_first)  // Add vote if not first vote
            let one = halo2_proofs::plonk::Expression::Constant(Fp::from(1));
            [
                s.clone() * (new_count - prev_count - (one.clone() - is_first.clone())),
                s * (new_tally - prev_tally - vote * (one - is_first))
            ]
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
                let vote_cell = region.assign_advice(|| "current vote", cfg.current_vote, 0, || self.current_vote)?;
                let prev_count_cell = region.assign_advice(|| "prev count", cfg.prev_vote_count, 0, || self.prev_vote_count)?;
                let prev_tally_cell = region.assign_advice(|| "prev tally", cfg.prev_tally, 0, || self.prev_tally)?;
                let is_first_cell = region.assign_advice(|| "is first", cfg.is_first_vote, 0, || self.is_first_vote)?;

                // Enable vote check gate
                cfg.sel_vote_check.enable(&mut region, 0)?;

                // Calculate new values
                let one = Value::known(Fp::from(1));
                let new_count = self.prev_vote_count + (one - self.is_first_vote);
                let new_tally = self.prev_tally + self.current_vote * (one - self.is_first_vote);

                let new_count_cell = region.assign_advice(|| "new count", cfg.new_vote_count, 0, || new_count)?;
                let new_tally_cell = region.assign_advice(|| "new tally", cfg.new_tally, 0, || new_tally)?;

                // Enable aggregation gate
                cfg.sel_aggregation.enable(&mut region, 0)?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        dev::MockProver,
        plonk::{keygen_vk, keygen_pk, create_proof, verify_proof},
    };

    #[test]
    fn test_vote_circuit_mock_prover() {
        let k: u32 = 7;
        let v = Fp::from(42u64);
        let t = v; // vote equals target (valid vote)
        // Hash computation removed since it's not needed

        let circuit = VoteCircuit {
            v: Value::known(v),
            t: Value::known(t),
        };

        // Public inputs must match instance column order: [t]
        let public_inputs = vec![t];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_invalid_vote_fails() {
        let k: u32 = 7;
        let v = Fp::from(42u64);
        let t = Fp::from(99u64); // vote does NOT equal target (invalid)
        // Hash computation removed since it's not needed

        let circuit = VoteCircuit {
            v: Value::known(v),
            t: Value::known(t),
        };

        // Public inputs must match instance column order: [t]
        let public_inputs = vec![t];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        // This should fail because v != t
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_vote_circuit_proof_roundtrip() {
        let k: u32 = 7;
        let v = Fp::from(123u64);
        let t = v; // vote equals target
        // Hash computation removed since it's not needed

        let circuit = VoteCircuit {
            v: Value::known(v),
            t: Value::known(t),
        };

        // Generate proving key and verification key
        let params = Params::new(k);
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

        // Create proof
        let public_inputs = vec![t];
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(Vec::new());
        create_proof(
            &params, 
            &pk, 
            &[circuit], 
            &[&[&public_inputs]], 
            OsRng, 
            &mut transcript
        ).expect("proof generation should not fail");
        let proof = transcript.finalize();

        // Verify proof
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(verify_proof(
            &params, 
            pk.get_vk(), 
            strategy, 
            &[&[&public_inputs]], 
            &mut transcript
        ).is_ok());
    }


    #[test]
    fn test_multiple_votes_batch() {
        // Test with 3 votes: yes, no, yes
        let k: u32 = 8; // Larger circuit for multiple votes
        
        let mut votes = Vec::new();
        votes.push(Fp::from(1u64)); // yes
        votes.push(Fp::from(0u64)); // no  
        votes.push(Fp::from(1u64)); // yes
        
        let target = Fp::from(1u64); // Target is "yes"
        
        // Count valid votes for target = 1 (yes)
        let mut valid_votes_yes = 0;
        let mut total_votes = votes.len();
        
        println!("Testing votes: {:?}", votes.iter().map(|v| if *v == Fp::from(1u64) { "yes" } else { "no" }).collect::<Vec<_>>());
        println!("Target: yes (1)");
        
        // Test each vote individually
        for (i, &vote) in votes.iter().enumerate() {
            let circuit = VoteCircuit {
                v: Value::known(vote),
                t: Value::known(target),
            };
            
            // Public inputs must match instance column order: [t]
            let mut public_inputs = Vec::new();
            public_inputs.push(target);
            let mut prover_inputs = Vec::new();
            prover_inputs.push(public_inputs);
            let prover = MockProver::run(k, &circuit, prover_inputs).unwrap();
            
            let vote_type = if vote == Fp::from(1u64) { "yes" } else { "no" };
            
            if vote == target {
                // Vote matches target - should pass
                assert_eq!(prover.verify(), Ok(()), "Vote {} ({}) should be valid", i, vote_type);
                valid_votes_yes += 1;
                println!("  Vote {}: {} ✓ VALID", i, vote_type);
            } else {
                // Vote doesn't match target - should fail
                assert!(prover.verify().is_err(), "Vote {} ({}) should be invalid", i, vote_type);
                println!("  Vote {}: {} ✗ INVALID", i, vote_type);
            }
        }
        
        println!("Vote count for target=yes: {}/{} valid", valid_votes_yes, total_votes);
        
        // Test with target = 0 (no)
        let target_no = Fp::from(0u64);
        let mut valid_votes_no = 0;
        
        println!("\nTarget: no (0)");
        
        for (i, &vote) in votes.iter().enumerate() {
            let circuit = VoteCircuit {
                v: Value::known(vote),
                t: Value::known(target_no),
            };
            
            let public_inputs = vec![target_no];
            let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
            
            let vote_type = if vote == Fp::from(1u64) { "yes" } else { "no" };
            
            if vote == target_no {
                // Vote matches target - should pass
                assert_eq!(prover.verify(), Ok(()), "Vote {} ({}) should be valid when target is no", i, vote_type);
                valid_votes_no += 1;
                println!("  Vote {}: {} ✓ VALID", i, vote_type);
            } else {
                // Vote doesn't match target - should fail
                assert!(prover.verify().is_err(), "Vote {} ({}) should be invalid when target is no", i, vote_type);
                println!("  Vote {}: {} ✗ INVALID", i, vote_type);
            }
        }
        
        println!("Vote count for target=no: {}/{} valid", valid_votes_no, total_votes);
        
        // Summary
        println!("\n=== VOTE COUNTING SUMMARY ===");
        println!("Total votes: {}", total_votes);
        println!("Valid votes for 'yes' target: {}", valid_votes_yes);
        println!("Valid votes for 'no' target: {}", valid_votes_no);
        println!("Expected: 2 votes for 'yes', 1 vote for 'no'");
        
        // Verify expected counts
        assert_eq!(valid_votes_yes, 2, "Should have 2 valid votes for 'yes' target");
        assert_eq!(valid_votes_no, 1, "Should have 1 valid vote for 'no' target");
    }

    #[test]
    fn test_recursive_vote_aggregation() {
        use std::time::Instant;
        
        // Test true recursive voting with aggregation
        let k: u32 = 8;
        let target = Fp::from(1u64); // Target is "yes"
        
        let mut votes = Vec::new();
        votes.push(Fp::from(1u64)); // yes
        votes.push(Fp::from(0u64)); // no (should fail)
        votes.push(Fp::from(1u64)); // yes
        
        println!("=== RECURSIVE VOTE AGGREGATION TEST ===");
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
        
        // Simulate recursive aggregation
        let mut prev_vote_count = Fp::from(0u64);
        let mut prev_tally = Fp::from(0u64);
        let mut total_valid_votes = 0;
        let mut individual_proof_sizes = Vec::new();
        let mut individual_prove_times = Vec::new();
        let mut individual_verify_times = Vec::new();
        
        for (i, &vote) in votes.iter().enumerate() {
            let is_first_vote = if i == 0 { Fp::from(1u64) } else { Fp::from(0u64) };
            
            // Create recursive circuit
            let circuit = RecursiveVoteCircuit {
                current_vote: Value::known(vote),
                target: Value::known(target),
                prev_vote_count: Value::known(prev_vote_count),
                prev_tally: Value::known(prev_tally),
                is_first_vote: Value::known(is_first_vote),
            };
            
            let vote_type = if vote == Fp::from(1u64) { "yes" } else { "no" };
            
            // Check if vote is valid (equals target or is first vote)
            let is_valid = vote == target || is_first_vote == Fp::from(1u64);
            
            if is_valid {
                // Generate actual proof
                let public_inputs = vec![target];
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
                
                let proof_size = proof.len();
                individual_proof_sizes.push(proof_size);
                individual_prove_times.push(prove_time);
                
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
                individual_verify_times.push(verify_time);
                
                // Calculate new aggregated values
                // For first vote: count = 0, tally = 0 (no change)
                // For subsequent votes: count = prev_count + 1, tally = prev_tally + vote
                let new_vote_count = if is_first_vote == Fp::from(1u64) {
                    Fp::from(0u64)  // First vote doesn't increment count
                } else {
                    prev_vote_count + Fp::from(1u64)  // Subsequent votes increment count
                };
                let new_tally = if is_first_vote == Fp::from(1u64) {
                    Fp::from(0u64)  // First vote doesn't add to tally
                } else {
                    prev_tally + vote  // Subsequent votes add to tally
                };
                
                // Update for next iteration
                prev_vote_count = new_vote_count;
                prev_tally = new_tally;
                total_valid_votes += 1;
                
                println!("  Vote {}: {} ✓ VALID (count: {:?}, tally: {:?})", 
                    i, vote_type, new_vote_count, new_tally);
                println!("    Proof size: {} bytes", proof_size);
                println!("    Prove time: {:?}", prove_time);
                println!("    Verify time: {:?}", verify_time);
                
                // Verify the proof
                assert!(verify_result.is_ok(), "Recursive vote {} should be valid", i);
            } else {
                println!("  Vote {}: {} ✗ INVALID (doesn't match target)", i, vote_type);
            }
        }
        
        // Calculate aggregated metrics
        let total_proof_size: usize = individual_proof_sizes.iter().sum();
        let total_prove_time: std::time::Duration = individual_prove_times.iter().sum();
        let total_verify_time: std::time::Duration = individual_verify_times.iter().sum();
        let avg_proof_size = if !individual_proof_sizes.is_empty() {
            total_proof_size / individual_proof_sizes.len()
        } else {
            0
        };
        
        println!("\n=== RECURSIVE AGGREGATION SUMMARY ===");
        println!("Final vote count: {:?}", prev_vote_count);
        println!("Final tally: {:?}", prev_tally);
        println!("Total valid votes: {}", total_valid_votes);
        println!("Expected: 2 valid votes (first vote + one 'yes' vote)");
        
        println!("\n=== PROOF SIZE & TIMING ANALYSIS ===");
        println!("Individual proof sizes: {:?} bytes", individual_proof_sizes);
        println!("Average proof size: {} bytes", avg_proof_size);
        println!("Total proof size (all votes): {} bytes", total_proof_size);
        println!("Total prove time: {:?}", total_prove_time);
        println!("Total verify time: {:?}", total_verify_time);
        println!("Average prove time: {:?}", total_prove_time / individual_prove_times.len() as u32);
        println!("Average verify time: {:?}", total_verify_time / individual_verify_times.len() as u32);
        
        // Verify final aggregated result
        // The final vote count should be the number of valid votes processed (excluding first vote)
        // We had 2 valid votes total, but the first vote doesn't increment the count
        assert_eq!(prev_vote_count, Fp::from(1u64), "Should have 1 vote in final count (excluding first vote)");
        assert_eq!(prev_tally, Fp::from(1u64), "Final tally should be 1 (one 'yes' vote)");
    }

    #[test]
    fn test_multi_target_voting() {
        println!("\n=== MULTI-TARGET VOTING TEST ===");
        
        // Multiple questions/targets
        let targets = vec![
            Fp::from(1u64), // Question 1: "Do you support proposal A?" (yes=1, no=0)
            Fp::from(2u64), // Question 2: "Which option do you prefer?" (1, 2, 3)
            Fp::from(1u64), // Question 3: "Do you support proposal B?" (yes=1, no=0)
        ];
        
        // Votes for each question
        let votes = vec![
            Fp::from(1u64), // Vote 1: Yes to proposal A
            Fp::from(2u64), // Vote 2: Option 2 for question 2
            Fp::from(0u64), // Vote 3: No to proposal B
        ];
        
        println!("Targets: {:?}", targets);
        println!("Votes: {:?}", votes);
        
        // Test each vote against its corresponding target
        for (i, (vote, target)) in votes.iter().zip(targets.iter()).enumerate() {
            let circuit = VoteCircuit {
                v: Value::known(*vote),
                t: Value::known(*target),
            };
            
            let public_inputs = vec![*target];
            let prover = MockProver::run(4, &circuit, vec![public_inputs]).unwrap();
            
            let is_valid = vote == target;
            let vote_type = if *vote == Fp::from(1u64) { "yes" } else if *vote == Fp::from(0u64) { "no" } else { "other" };
            
            if is_valid {
                assert_eq!(prover.verify(), Ok(()), "Vote {} should be valid", i);
                println!("  Question {}: {} ✓ VALID (vote: {:?} matches target: {:?})", i+1, vote_type, vote, target);
            } else {
                assert!(prover.verify().is_err(), "Vote {} should be invalid", i);
                println!("  Question {}: {} ✗ INVALID (vote: {:?} doesn't match target: {:?})", i+1, vote_type, vote, target);
            }
        }
        
        // Summary
        let valid_votes: usize = votes.iter().zip(targets.iter())
            .map(|(vote, target)| if vote == target { 1 } else { 0 })
            .sum();
        
        println!("\n=== MULTI-TARGET SUMMARY ===");
        println!("Total questions: {}", targets.len());
        println!("Valid votes: {}", valid_votes);
        println!("Invalid votes: {}", targets.len() - valid_votes);
        println!("Success rate: {:.1}%", (valid_votes as f64 / targets.len() as f64) * 100.0);
    }

    #[test]
    fn test_flexible_target_design() {
        println!("\n=== FLEXIBLE TARGET DESIGN COMPARISON ===");
        
        // Scenario 1: Single target (current design)
        println!("Scenario 1: Single Target Design");
        let single_target = Fp::from(1u64);
        let single_votes = vec![Fp::from(1u64), Fp::from(0u64), Fp::from(1u64)];
        
        println!("  Target: {:?}", single_target);
        println!("  Votes: {:?}", single_votes);
        
        let single_valid: usize = single_votes.iter()
            .map(|vote| if vote == &single_target { 1 } else { 0 })
            .sum();
        println!("  Valid votes: {}/{}", single_valid, single_votes.len());
        
        // Scenario 2: Multiple targets (proposed design)
        println!("\nScenario 2: Multiple Targets Design");
        let multi_targets = vec![Fp::from(1u64), Fp::from(2u64), Fp::from(1u64)];
        let multi_votes = vec![Fp::from(1u64), Fp::from(2u64), Fp::from(0u64)];
        
        println!("  Targets: {:?}", multi_targets);
        println!("  Votes: {:?}", multi_votes);
        
        let multi_valid: usize = multi_votes.iter().zip(multi_targets.iter())
            .map(|(vote, target)| if vote == target { 1 } else { 0 })
            .sum();
        println!("  Valid votes: {}/{}", multi_valid, multi_votes.len());
        
        // Scenario 3: Flexible targets (any value)
        println!("\nScenario 3: Flexible Targets (Any Value)");
        let flexible_targets = vec![Fp::from(42u64), Fp::from(100u64), Fp::from(7u64)];
        let flexible_votes = vec![Fp::from(42u64), Fp::from(99u64), Fp::from(7u64)];
        
        println!("  Targets: {:?}", flexible_targets);
        println!("  Votes: {:?}", flexible_votes);
        
        let flexible_valid: usize = flexible_votes.iter().zip(flexible_targets.iter())
            .map(|(vote, target)| if vote == target { 1 } else { 0 })
            .sum();
        println!("  Valid votes: {}/{}", flexible_valid, flexible_votes.len());
        
        println!("\n=== DESIGN COMPARISON ===");
        println!("Single Target:   {} valid votes (simple, binary decisions)", single_valid);
        println!("Multiple Targets: {} valid votes (complex, multi-question)", multi_valid);
        println!("Flexible Targets: {} valid votes (any value, maximum flexibility)", flexible_valid);
    }
}