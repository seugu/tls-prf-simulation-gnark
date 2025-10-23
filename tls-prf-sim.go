package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

const MsgLen = 3831 // ≈60 SHA-256 compressions (512-byte blocks)

type Sha256Circuit struct {
	Msg    [MsgLen]frontend.Variable
	Len    frontend.Variable     `gnark:",public"`
	Digest [32]frontend.Variable `gnark:",public"`
}

func (c *Sha256Circuit) Define(api frontend.API) error {
	h, _ := sha2.New(api)
	B, _ := uints.NewBytes(api)

	in := make([]uints.U8, 0, MsgLen)
	for i := 0; i < MsgLen; i++ {
		in = append(in, B.ValueOf(c.Msg[i]))
	}
	h.Write(in)
	sum := h.Sum()

	for i := 0; i < 32; i++ {
		api.AssertIsEqual(B.Value(sum[i]), c.Digest[i])
	}
	return nil
}

func main() {
	var circuit Sha256Circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, MsgLen)
	for i := 0; i < MsgLen; i++ {
		msg[i] = byte(i % 256)
	}
	d := sha256.Sum256(msg)

	w := Sha256Circuit{Len: MsgLen}
	for i := 0; i < MsgLen; i++ {
		w.Msg[i] = msg[i]
	}
	for i := 0; i < 32; i++ {
		w.Digest[i] = d[i]
	}

	privW, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	pubW, err := privW.Public()
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(ccs, pk, privW)
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, pubW)
	fmt.Println("Verify error:", err)
}
