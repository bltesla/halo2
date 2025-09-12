Halo2 examples

This folder contains small examples that illustrate different parts of Halo2.

Prereqs
- Rust toolchain (matching repo toolchain)
- From repo root: `/workspaces/halo2`

Basic circuits
- simple-add.rs
  - Tiny circuit enforcing a + b = c; prints a proof size
  - Run: `cargo run -p halo2_proofs --example simple-add`
- simple-add-prover.rs
  - End-to-end: keygen, create_proof, verify_proof for a + b = c
  - Run: `cargo run -p halo2_proofs --example simple-add-prover`
- simple-example.rs
  - Mixed demo of advice/fixed columns, selectors, custom gate
  - Run: `cargo run -p halo2_proofs --example simple-example`

Chips and composition
- two-chip.rs
  - Reusable chips (AddChip, MulChip), composed via FieldChip; exposes public output; uses MockProver
  - Run: `cargo run -p halo2_proofs --example two-chip`

Layout visualization
- circuit-layout.rs
  - Renders a circuit’s column layout to an image (dev graph tooling)
  - Requires feature: `--features test-dev-graph`
  - Run: `cargo run -p halo2_proofs --example circuit-layout --features test-dev-graph`
  - Output: `layout.png`

Cost and sizing estimator
- cost-model.rs
  - Estimates proof size and verification time from declarative column/gate/lookup/permutation spec
  - Help: `cargo run -p halo2_proofs --example cost-model -- --help`
  - Example:
    - `cargo run -p halo2_proofs --example cost-model --  20 --advice 0,1 --fixed 0 --gate-degree 2 --lookup 2,1,1 --permutation 3`

Notes
- k is the log2 domain size (rows n = 2^k). Small examples use k=4; increase for larger circuits.
- MockProver is useful for fast sanity checks without full proving.
- For public inputs, use an instance column and pass instances to both proving and verifying.

