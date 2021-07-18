package main

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/sha3"
	"hash/fnv"
	"main/rathash"
	"math/big"
	"math/rand"
	"runtime"
	"testing"
	"time"
)

// Copyright © 2021 Matthew R Bonnette. Openly-licensed under a BSD-3-Clause license.
/* This program is the hardly-rigorous testing suite for the Go implementation of the RatHash
function in direct comparison to other, properly-vetted cryptographic hashing algorithms. It aims to
test the following characteristics: deterministicness, extremely short-term collision-resistance,
and mean bias per output bit. Furthermore, it benchmarks the relative throughput and memory usage of
each algorithm. */

const (
	ints   = 5e4
	passes = 3
	kiB    = 1024
)

var (
	intBytes  = make([]byte, 4)
	randBytes []byte
	numbers   = map[uint32]*big.Int{}
	random    = map[uint32]*big.Int{}
	length    = 512
)

func printMeanBias(hashes map[uint32]*big.Int, ln int) {
	tally := make([]float64, ln)
	for i := range hashes {
		for i2 := ln - 1; i2 >= 0; i2-- {
			if hashes[i].Bit(i2) == 1 {
				tally[i2]++
			}
		}
	}
	var total float64
	for i := range tally {
		tally[i] = tally[i] - ints/2
		if tally[i] < 0 {
			tally[i] *= -1
		}
		total += tally[i]
	}
	// fmt.Println(hashes)
	fmt.Printf("%5.3f%%\n", (total/float64(ln))/(ints/2)*100)
	// fmt.Println(tally)
}

func makeBytes(size int64) {
	randBytes = make([]byte, size)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic("failed to generate random data")
	}
}

func test(key string) {
	switch key {
	case "rat":
		length = runtime.NumCPU() * 64
		if length < 256 {
			length = 256
		}
		for i := uint32(ints) - 1; int32(i) > -1; i-- {
			binary.BigEndian.PutUint32(intBytes, i)
			numbers[i] = big.NewInt(0).SetBytes(rathash.Sum(intBytes, length))
			makeBytes(kiB)
			random[i] = big.NewInt(0).SetBytes(rathash.Sum(randBytes, length))
		}
	case "fnv":
		length = 128
		for i := uint32(ints) - 1; int32(i) > -1; i-- {
			binary.BigEndian.PutUint32(intBytes, i)
			hash := fnv.New128a()
			hash.Write(intBytes)
			var tmp []byte
			numbers[i] = big.NewInt(0).SetBytes(hash.Sum(tmp))
			makeBytes(kiB)
			hash.Write(randBytes)
			tmp = nil
			random[i] = big.NewInt(0).SetBytes(hash.Sum(tmp))
		}
	case "sha1":
		length = 160
		for i := uint32(ints) - 1; int32(i) > -1; i-- {
			binary.BigEndian.PutUint32(intBytes, i)
			tmp := sha1.Sum(intBytes)
			numbers[i] = big.NewInt(0).SetBytes(tmp[:])
			makeBytes(kiB)
			tmp = sha1.Sum(randBytes)
			random[i] = big.NewInt(0).SetBytes(tmp[:])
		}
	case "sha2":
		for i := uint32(ints) - 1; int32(i) > -1; i-- {
			binary.BigEndian.PutUint32(intBytes, i)
			tmp := sha512.Sum512(intBytes)
			numbers[i] = big.NewInt(0).SetBytes(tmp[:])
			makeBytes(kiB)
			tmp = sha512.Sum512(randBytes)
			random[i] = big.NewInt(0).SetBytes(tmp[:])
		}
	case "sha3":
		for i := uint32(ints) - 1; int32(i) > -1; i-- {
			binary.BigEndian.PutUint32(intBytes, i)
			tmp := sha3.Sum512(intBytes)
			numbers[i] = big.NewInt(0).SetBytes(tmp[:])
			makeBytes(kiB)
			tmp = sha3.Sum512(randBytes)
			random[i] = big.NewInt(0).SetBytes(tmp[:])
		}
	case "blake3":
		for i := uint32(ints) - 1; int32(i) > -1; i-- {
			binary.BigEndian.PutUint32(intBytes, i)
			tmp := blake3.Sum512(intBytes)
			numbers[i] = big.NewInt(0).SetBytes(tmp[:])
			makeBytes(kiB)
			tmp = blake3.Sum512(randBytes)
			random[i] = big.NewInt(0).SetBytes(tmp[:])
		}
	}
	printMeanBias(numbers, length)
	printMeanBias(random, length)
}

/* SHA-256 is faster only on ARM, SHA-512 is faster on most other architectures. */
func rat(name string, size int64) {
	makeBytes(size)
	length = runtime.NumCPU() * 64
	if length < 256 {
		length = 256
	}
	fn := func(b *testing.B) {
		b.SetBytes(size)
		for i := b.N; i > 0; i-- {
			_ = rathash.Sum(randBytes, length)
		}
	}
	r := testing.Benchmark(fn)
	speed := float64(r.Bytes*int64(r.N)) / float64(r.T.Nanoseconds()) * 1e3
	usage := float64(r.AllocedBytesPerOp()) / 1e6
	fmt.Printf(name+"      %7.2fMB/s      %7.2fMB/op\n", speed, usage)
}

func b3(name string, size int64) {
	makeBytes(size)
	fn := func(b *testing.B) {
		b.SetBytes(size)
		for i := b.N; i > 0; i-- {
			_ = blake3.Sum512(randBytes)
		}
	}
	r := testing.Benchmark(fn)
	speed := float64(r.Bytes*int64(r.N)) / float64(r.T.Nanoseconds()) * 1e3
	usage := float64(r.AllocedBytesPerOp()) / 1e6
	fmt.Printf(name+"      %7.2fMB/s      %7.2fMB/op\n", speed, usage)
}

func main() {
	fmt.Printf("Running benchmarks on %d CPUs!\n\n"+
		"Function:         Speed:           Usage:\n", runtime.NumCPU())

	t := time.Now()
	test("rat")
	test("fnv")
	// panic("using panic to exit early saves the use of another import")
	test("sha1")
	test("sha2")
	test("sha3")
	test("blake3")

	rat("RatHash-8B ", 8)
	b3("BLAKE3-8B  ", 8)
	println()
	rat("RatHash-64M", kiB*kiB*64)
	b3("BLAKE3-64M ", kiB*kiB*64)
	println()
	rat("RatHash-1G ", kiB*kiB*kiB)
	b3("BLAKE3-1G  ", kiB*kiB*kiB)

	fmt.Printf("\nFinished in %s on %s/%s.\n", time.Since(t), runtime.GOOS, runtime.GOARCH)
}
