export CGO_LDFLAGS="-L/workspaces/halo2/target/release "
export LD_LIBRARY_PATH=/workspaces/halo2/target/release:$LD_LIBRARY_PATH
# cd /workspaces/halo2/simple_add_go
# Ensure proof exists
[ -f ../proof.bin ] || (cd .. && cargo run -p simple_vote_recursive_proof)
go run .