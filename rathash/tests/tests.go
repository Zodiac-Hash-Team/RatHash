package main

import (
	"encoding/binary"
	"fmt"
	"github.com/zeebo/blake3"
	"main/rathash"
	"math/big"
	"math/rand"
	"runtime"
	"testing"
	"time"
)

// Copyright © 2021 Matthew R Bonnette. Licensed under a BSD-3-Clause license.
/* This program is the hardly-rigorous testing suite for the Go implementation of the RatHash
function in direct comparison to other, properly-vetted cryptographic hashing algorithms. It aims to
test the following characteristics: deterministicness, extremely short-term collision-resistance,
and mean bias per output bit. Furthermore, it benchmarks the relative throughput and memory usage of
each algorithm. */

const (
	ints  = uint32(5e4)
	size1 = 8
	size2 = 4 * 1024
	size3 = 2 * 1024 * 1024
	size4 = 1 * 1024 * 1024 * 1024
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
	fmt.Printf("%5.3f%%\n", (total/float64(ln))/float64(ints/2)*100)
}

func makeBytes(size int64) {
	rBytes = make([]byte, size)
	_, err := rand.Read(rBytes)
	if err != nil {
		panic("failed to generate random data")
	}
}

func ratTest() {
	length = 512
	for i := ints - 1; int32(i) > -1; i-- {
		binary.BigEndian.PutUint32(iBytes, i)
		integers[i] = big.NewInt(0).SetBytes(rathash.Sum(iBytes, length))
		makeBytes(size2)
		random[i] = big.NewInt(0).SetBytes(rathash.Sum(rBytes, length))
	}
	printMeanBias(integers, length)
	printMeanBias(random, length)
}

func ratBench(name string, size int64) {
	makeBytes(size)
	length = 512
	fn := func(b *testing.B) {
		b.SetBytes(size)
		for i := b.N; i > 0; i-- {
			_ = rathash.Sum(rBytes, length)
		}
	}
	r := testing.Benchmark(fn)
	speed := float64(r.Bytes*int64(r.N)) / float64(r.T.Nanoseconds()) * 1e3
	fmt.Printf(name+"      %7.2fMB/s      %dB/op\n", speed, r.AllocedBytesPerOp())
}

func b3Bench(name string, size int64) {
	makeBytes(size)
	fn := func(b *testing.B) {
		b.SetBytes(size)
		for i := b.N; i > 0; i-- {
			_ = blake3.Sum512(rBytes)
		}
	}
	r := testing.Benchmark(fn)
	speed := float64(r.Bytes*int64(r.N)) / float64(r.T.Nanoseconds()) * 1e3
	fmt.Printf(name+"      %7.2fMB/s      %dB/op\n", speed, r.AllocedBytesPerOp())
}

func main() {
	fmt.Printf("Running benchmarks on %d CPUs!\n\n"+
		"Function:         Speed:           Usage:\n", runtime.NumCPU())

	t := time.Now()
	ratTest()
	ratBench("RatHash-8B ", size1)
	b3Bench("BLAKE3-8B  ", size1)
	println()
	ratBench("RatHash-64M", size3*32)
	b3Bench("BLAKE3-64M ", size3*32)
	println()
	ratBench("RatHash-1G ", size4)
	b3Bench("BLAKE3-1G  ", size4)

	fmt.Printf("\nFinished in %s on %s/%s.\n", time.Since(t), runtime.GOOS, runtime.GOARCH)
}
