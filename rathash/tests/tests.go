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
	ints uint32 = 5e4
	kiB         = 1024
)

var (
	iBytes   = make([]byte, 4)
	rBytes   []byte
	integers = map[uint32]*big.Int{}
	random   = map[uint32]*big.Int{}
	length   = 512
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
		tally[i] = tally[i] - float64(ints)/2
		if tally[i] < 0 {
			tally[i] *= -1
		}
		total += tally[i]
	}
	// fmt.Println(hashes)
	fmt.Printf("%5.3f%%\n", (total/float64(ln))/float64(ints/2)*100)
	// fmt.Println(tally)
}

func makeBytes(size int64) {
	rBytes = make([]byte, size)
	_, err := rand.Read(rBytes)
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
		for i := ints - 1; int32(i) > -1; i-- {
			binary.BigEndian.PutUint32(iBytes, i)
			integers[i] = big.NewInt(0).SetBytes(rathash.Sum(iBytes, length))
			makeBytes(kiB * 2)
			random[i] = big.NewInt(0).SetBytes(rathash.Sum(rBytes, length))
		}
	case "fnv":
		length = 128
		for i := ints - 1; int32(i) > -1; i-- {
			binary.BigEndian.PutUint32(iBytes, i)
			hash := fnv.New128a()
			hash.Write(iBytes)
			var tmp []byte
			integers[i] = big.NewInt(0).SetBytes(hash.Sum(tmp))
			makeBytes(kiB * 2)
			hash.Write(rBytes)
			tmp = nil
			random[i] = big.NewInt(0).SetBytes(hash.Sum(tmp))
		}
	case "sha1":
		length = 160
		for i := ints - 1; int32(i) > -1; i-- {
			binary.BigEndian.PutUint32(iBytes, i)
			tmp := sha1.Sum(iBytes)
			integers[i] = big.NewInt(0).SetBytes(tmp[:])
			makeBytes(kiB * 2)
			tmp = sha1.Sum(rBytes)
			random[i] = big.NewInt(0).SetBytes(tmp[:])
		}
	case "sha2":
		for i := ints - 1; int32(i) > -1; i-- {
			binary.BigEndian.PutUint32(iBytes, i)
			tmp := sha512.Sum512(iBytes)
			integers[i] = big.NewInt(0).SetBytes(tmp[:])
			makeBytes(kiB * 2)
			tmp = sha512.Sum512(rBytes)
			random[i] = big.NewInt(0).SetBytes(tmp[:])
		}
	case "sha3":
		for i := ints - 1; int32(i) > -1; i-- {
			binary.BigEndian.PutUint32(iBytes, i)
			tmp := sha3.Sum512(iBytes)
			integers[i] = big.NewInt(0).SetBytes(tmp[:])
			makeBytes(kiB * 2)
			tmp = sha3.Sum512(rBytes)
			random[i] = big.NewInt(0).SetBytes(tmp[:])
		}
	case "blake3":
		for i := ints - 1; int32(i) > -1; i-- {
			binary.BigEndian.PutUint32(iBytes, i)
			tmp := blake3.Sum512(iBytes)
			integers[i] = big.NewInt(0).SetBytes(tmp[:])
			makeBytes(kiB * 2)
			tmp = blake3.Sum512(rBytes)
			random[i] = big.NewInt(0).SetBytes(tmp[:])
		}
	}
	printMeanBias(integers, length)
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
			_ = rathash.Sum(rBytes, length)
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
			_ = blake3.Sum512(rBytes)
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
