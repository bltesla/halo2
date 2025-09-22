package main

/*
#cgo LDFLAGS: -L./target/release -lsimple_vote_recursive_proof
extern int create_recursive_vote_proof(unsigned int k, unsigned char vote, 
                                       unsigned char* prev_total_ptr, unsigned int prev_total_len,
                                       unsigned char* prev_yes_ptr, unsigned int prev_yes_len,
                                       unsigned char* prev_no_ptr, unsigned int prev_no_len,
                                       unsigned char** proof_ptr, unsigned long long* proof_len,
                                       unsigned char** public_ptr, unsigned long long* public_len);
extern int verify_recursive_vote_proof(unsigned int k, unsigned char vote,
                                      unsigned char* prev_total_ptr, unsigned int prev_total_len,
                                      unsigned char* prev_yes_ptr, unsigned int prev_yes_len,
                                      unsigned char* prev_no_ptr, unsigned int prev_no_len,
                                      unsigned char* proof_ptr, unsigned long long proof_len,
                                      unsigned char* public_ptr, unsigned long long public_len);
extern void free_recursive_vote_bytes(unsigned char* ptr, unsigned long long len);
*/
import "C"
import (
	"fmt"
	"time"
	"unsafe"
)

// Vote represents a single vote in the recursive chain
type Vote struct {
	Value byte // 0 = No, 1 = Yes
}

// VoteState represents the current aggregated state
type VoteState struct {
	TotalVotes uint64
	YesVotes   uint64
	NoVotes    uint64
}

// ProofData holds a proof and its associated public outputs
type ProofData struct {
	Proof  []byte
	Public []byte
}

func main() {
	fmt.Println("🗳️  RECURSIVE VOTING PROOF SYSTEM")
	fmt.Println("=====================================")
	
	k := C.uint(8) // Circuit size parameter
	votes := []Vote{
		{Value: 1}, // Yes
		{Value: 0}, // No  
		{Value: 1}, // Yes
	}
	
	fmt.Printf("📊 Testing with %d votes: ", len(votes))
	for i, vote := range votes {
		if vote.Value == 1 {
			fmt.Print("Yes")
		} else {
			fmt.Print("No")
		}
		if i < len(votes)-1 {
			fmt.Print(", ")
		}
	}
	fmt.Println()
	
	var currentState VoteState
	var proofs []ProofData
	var totalProveTime time.Duration
	var totalVerifyTime time.Duration
	var totalProofSize uint64
	
	// Process each vote recursively
	for i, vote := range votes {
		isFirst := i == 0
		fmt.Printf("\n--- Processing Vote %d: %s ---\n", i+1, 
			map[byte]string{0: "No", 1: "Yes"}[vote.Value])
		
		if isFirst {
			fmt.Println("📝 Genesis vote (no previous state)")
		} else {
			fmt.Printf("🔗 Recursive vote (prev: %d total, %d yes, %d no)\n", 
				currentState.TotalVotes, currentState.YesVotes, currentState.NoVotes)
		}
		
		// Prepare previous state (empty for first vote)
		var prevTotal, prevYes, prevNo []byte
		if !isFirst {
			prevTotal = uint64ToBytes(currentState.TotalVotes)
			prevYes = uint64ToBytes(currentState.YesVotes)
			prevNo = uint64ToBytes(currentState.NoVotes)
		}
		
		// Generate proof
		fmt.Println("⚡ Generating proof...")
		proofStart := time.Now()
		
		var proofPtr *C.uchar
		var proofLen C.ulonglong
		var publicPtr *C.uchar
		var publicLen C.ulonglong
		
		result := C.create_recursive_vote_proof(
			k,
			C.uchar(vote.Value),
			bytesToCPtr(prevTotal), C.uint(len(prevTotal)),
			bytesToCPtr(prevYes), C.uint(len(prevYes)),
			bytesToCPtr(prevNo), C.uint(len(prevNo)),
			&proofPtr, &proofLen,
			&publicPtr, &publicLen,
		)
		
		proofTime := time.Since(proofStart)
		totalProveTime += proofTime
		
		if result != 0 {
			panic(fmt.Sprintf("Failed to create proof for vote %d", i+1))
		}
		
		// Convert C pointers to Go slices
		proofBytes := C.GoBytes(unsafe.Pointer(proofPtr), C.int(proofLen))
		publicBytes := C.GoBytes(unsafe.Pointer(publicPtr), C.int(publicLen))
		totalProofSize += uint64(len(proofBytes))
		
		fmt.Printf("✅ Proof generated: %d bytes (%.2f KB) in %v\n", 
			len(proofBytes), float64(len(proofBytes))/1024.0, proofTime)
		
		// Verify proof
		fmt.Println("🔍 Verifying proof...")
		verifyStart := time.Now()
		
		verifyResult := C.verify_recursive_vote_proof(
			k,
			C.uchar(vote.Value),
			bytesToCPtr(prevTotal), C.uint(len(prevTotal)),
			bytesToCPtr(prevYes), C.uint(len(prevYes)),
			bytesToCPtr(prevNo), C.uint(len(prevNo)),
			(*C.uchar)(unsafe.Pointer(&proofBytes[0])), C.ulonglong(len(proofBytes)),
			(*C.uchar)(unsafe.Pointer(&publicBytes[0])), C.ulonglong(len(publicBytes)),
		)
		
		verifyTime := time.Since(verifyStart)
		totalVerifyTime += verifyTime
		
		if verifyResult != 0 {
			panic(fmt.Sprintf("Failed to verify proof for vote %d", i+1))
		}
		
		fmt.Printf("✅ Proof verified in %v\n", verifyTime)
		
		// Parse public outputs to update state
		newState := parsePublicOutputs(publicBytes)
		fmt.Printf("📈 New state: %d total, %d yes, %d no\n", 
			newState.TotalVotes, newState.YesVotes, newState.NoVotes)
		
		// Store proof and update state
		proofs = append(proofs, ProofData{
			Proof:  make([]byte, len(proofBytes)),
			Public: make([]byte, len(publicBytes)),
		})
		copy(proofs[i].Proof, proofBytes)
		copy(proofs[i].Public, publicBytes)
		currentState = newState
		
		// Clean up C memory
		C.free_recursive_vote_bytes(proofPtr, proofLen)
		C.free_recursive_vote_bytes(publicPtr, publicLen)
	}
	
	// Final results
	fmt.Println("\n🎯 FINAL RESULTS")
	fmt.Println("=================")
	fmt.Printf("📊 Vote Summary:\n")
	fmt.Printf("   Total Votes: %d\n", currentState.TotalVotes)
	fmt.Printf("   Yes Votes:   %d\n", currentState.YesVotes)
	fmt.Printf("   No Votes:    %d\n", currentState.NoVotes)
	
	fmt.Printf("\n⚡ Performance Metrics:\n")
	fmt.Printf("   Total Proofs:     %d\n", len(proofs))
	fmt.Printf("   Total Proof Size: %d bytes (%.2f KB)\n", 
		totalProofSize, float64(totalProofSize)/1024.0)
	fmt.Printf("   Avg Proof Size:   %d bytes\n", totalProofSize/uint64(len(proofs)))
	fmt.Printf("   Total Prove Time: %v\n", totalProveTime)
	fmt.Printf("   Total Verify Time: %v\n", totalVerifyTime)
	fmt.Printf("   Avg Prove Time:   %v\n", totalProveTime/time.Duration(len(proofs)))
	fmt.Printf("   Avg Verify Time:  %v\n", totalVerifyTime/time.Duration(len(proofs)))
	
	// Verify final tally matches input
	expectedYes := 0
	expectedNo := 0
	for _, vote := range votes {
		if vote.Value == 1 {
			expectedYes++
		} else {
			expectedNo++
		}
	}
	
	if currentState.YesVotes != uint64(expectedYes) || currentState.NoVotes != uint64(expectedNo) {
		panic(fmt.Sprintf("Tally mismatch! Expected: %d yes, %d no. Got: %d yes, %d no", 
			expectedYes, expectedNo, currentState.YesVotes, currentState.NoVotes))
	}
	
	fmt.Println("\n✅ Recursive voting proof system completed successfully!")
	fmt.Printf("🔗 Generated %d linked proofs with total size of %.2f KB\n", 
		len(proofs), float64(totalProofSize)/1024.0)
}

// Helper functions

func uint64ToBytes(n uint64) []byte {
	if n == 0 {
		return []byte{}
	}
	// Simple encoding - in production use proper serialization
	result := make([]byte, 8)
	for i := 0; i < 8; i++ {
		result[i] = byte(n >> (8 * i))
	}
	return result
}

func bytesToCPtr(data []byte) *C.uchar {
	if len(data) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&data[0]))
}

func parsePublicOutputs(publicBytes []byte) VoteState {
	// Simple parsing - in production use proper deserialization
	// For now, assume the public outputs are encoded as 3 field elements
	// Each field element represents total, yes, no respectively
	
	if len(publicBytes) < 24 { // At least 3 * 8 bytes
		return VoteState{}
	}
	
	// Parse as little-endian uint64s (simplified)
	total := uint64(0)
	yes := uint64(0)
	no := uint64(0)
	
	// In a real implementation, you'd properly deserialize field elements
	// For demo purposes, we'll extract the lower bytes
	if len(publicBytes) >= 8 {
		total = uint64(publicBytes[0])
	}
	if len(publicBytes) >= 16 {
		yes = uint64(publicBytes[8])
	}
	if len(publicBytes) >= 24 {
		no = uint64(publicBytes[16])
	}
	
	return VoteState{
		TotalVotes: total,
		YesVotes:   yes,
		NoVotes:    no,
	}
}
