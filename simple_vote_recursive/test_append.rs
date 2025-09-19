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

        // Public inputs: [total_votes, yes_votes, no_votes]
        let public_inputs = vec![
            Fp::from(1), // Expected total: 1 vote
            Fp::from(1), // Expected yes: 1 vote  
            Fp::from(0), // Expected no: 0 votes
        ];
        
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
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

        // Public inputs: [total_votes, yes_votes, no_votes]
        let public_inputs = vec![
            vec![Fp::from(1)], // Expected total: 1 vote
            vec![Fp::from(1)], // Expected yes: 1 vote  
            vec![Fp::from(0)], // Expected no: 0 votes
        ];
        let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
        
        // let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        prover.assert_satisfied();
        println!("✅ No vote accepted and counted correctly");
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

        // Any public inputs (doesn't matter since circuit should fail)
        let public_inputs = vec![
            Fp::from(1),
            Fp::from(0),
            Fp::from(1),
        ];
        
        let prover = MockProver::run(k, &circuit, vec![public_inputs])
            .expect("MockProver should not fail");
        
        // This should fail because vote (2) is not in {0, 1}
        match prover.verify() {
            Ok(_) => panic!("Invalid vote should have been rejected!"),
            Err(_) => println!("✅ Invalid vote correctly rejected by binary constraint"),
        }
    }
}
