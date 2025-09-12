package main

/*
#cgo LDFLAGS: -L../target/release -lsimple_vote_ffi

extern int create_simple_vote_proof(unsigned int k, unsigned long long t_public, unsigned long long v_private, unsigned char** out_ptr, unsigned long* out_len);
extern int verify_simple_vote_proof(unsigned int k, unsigned long long t_public, const unsigned char* proof_ptr, unsigned long proof_len);
extern void free_simple_vote_bytes(unsigned char* ptr, unsigned long len);
*/
import "C"

import (
    "fmt"
    // "io/ioutil"
    "time"
    // "unsafe"
)

func main() {

    k := C.uint(4)
    t := C.ulonglong(99) // claimed tally increment (public)
    v := C.ulonglong(99) // private vote bit

    var outPtr *C.uchar
    var outLen C.ulong

	createAndVerifyVoteProof(k, t, v, &outPtr, &outLen)

	t = C.ulonglong(99) // claimed tally increment (public)
    v = C.ulonglong(100) // private vote bit

	createAndVerifyVoteProof(k, t, v, &outPtr, &outLen)

}

func createAndVerifyVoteProof(k C.uint, t, v C.ulonglong, outPtr **C.uchar, outLen *C.ulong) {
	fmt.Printf(" test case for t=%d, v=%d\n", t, v)

	startProve := time.Now()
	if C.create_simple_vote_proof(k, t, v, outPtr, outLen) != 0 {
		panic("Failed to create vote proof")
	}
	proveMs := time.Since(startProve).Milliseconds()
	defer C.free_simple_vote_bytes(*outPtr, *outLen)

	startVerify := time.Now()
	if C.verify_simple_vote_proof(k, t, *outPtr, *outLen) != 0 {
		fmt.Println("vote proof verification failed")
	}
	verifyMs := time.Since(startVerify).Milliseconds()

	fmt.Printf("proof size: %d bytes. prove=%dms verify=%dms\n\n", uint64(*outLen), proveMs, verifyMs)

	// proofBytes := C.GoBytes(unsafe.Pointer(*outPtr), C.int(*outLen))
	// if err := ioutil.WriteFile("../proof_vote.bin", proofBytes, 0644); err != nil {
	// 	panic(fmt.Sprintf("Failed to write vote proof: %v", err))
	// }
}
