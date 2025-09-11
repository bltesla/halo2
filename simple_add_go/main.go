package main

/*
#cgo LDFLAGS: -L../target/release -lsimple_add_ffi

extern int create_simple_add_proof(unsigned int k, unsigned long long a, unsigned long long b, unsigned char** out_ptr, unsigned long* out_len);
extern int verify_simple_add_proof(unsigned int k, unsigned long long a, unsigned long long b, const unsigned char* proof_ptr, unsigned long proof_len);
extern void free_simple_add_bytes(unsigned char* ptr, unsigned long len);
*/
import "C"

import (
    "fmt"
    "io/ioutil"
    "time"
    "unsafe"
)

func main() {

    k := C.uint(4)
    a := C.ulonglong(2)
    b := C.ulonglong(3)

    var outPtr *C.uchar
    var outLen C.ulong
    startProve := time.Now()
    res := C.create_simple_add_proof(k, a, b, &outPtr, &outLen)
    if res != 0 {
        panic("Failed to create proof")
    }
    proveMs := time.Since(startProve).Milliseconds()
    defer C.free_simple_add_bytes(outPtr, outLen)

    // Verify the generated proof
    startVerify := time.Now()
    if C.verify_simple_add_proof(k, a, b, outPtr, outLen) != 0 { panic("verify failed") }
    verifyMs := time.Since(startVerify).Milliseconds()

    fmt.Printf("Proof created and verified successfully. size=%d bytes, prove=%dms, verify=%dms\n", uint64(outLen), proveMs, verifyMs)

    // Save proof to file
    proofBytes := C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen))
    if err := ioutil.WriteFile("../proof.bin", proofBytes, 0644); err != nil {
        panic(fmt.Sprintf("Failed to write proof: %v", err))
    }
    fmt.Println("Proof saved to proof.bin")



    // proof, err := ioutil.ReadFile("../proof.bin")
    // if err != nil {
    //     panic(err)
    // }
    // res := C.verify_simple_add_proof(k, a, b, (*C.uchar)(&proof[0]), C.ulong(len(proof)))
    // if res == 0 {
    //     fmt.Println("Go: proof verified successfully")
    // } else {
    //     fmt.Println("Go: proof verification failed")
    // }
}


