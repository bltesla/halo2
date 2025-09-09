package main

/*
#cgo LDFLAGS: -L../target/release -lsimple_add_ffi

extern int verify_simple_add_proof(unsigned int k, unsigned long long a, unsigned long long b, const unsigned char* proof_ptr, unsigned long proof_len);
*/
import "C"

import (
    "fmt"
    "io/ioutil"
)

func main() {
    proof, err := ioutil.ReadFile("../proof.bin")
    if err != nil {
        panic(err)
    }

    k := C.uint(4)
    a := C.ulonglong(2)
    b := C.ulonglong(3)
    res := C.verify_simple_add_proof(k, a, b, (*C.uchar)(&proof[0]), C.ulong(len(proof)))
    if res == 0 {
        fmt.Println("Go: proof verified successfully")
    } else {
        fmt.Println("Go: proof verification failed")
    }
}


