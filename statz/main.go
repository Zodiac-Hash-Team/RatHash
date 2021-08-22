package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/dterei/gotsc"
	"github.com/p7r0x7/rathash/rathash"
	"github.com/zeebo/blake3"
	"math/rand"
	"runtime"
	"testing"
	"time"
)

// Copyright © 2021 Matthew R Bonnette. Licensed under a BSD-3-Clause license.

const ints = uint32(5e4)

var (
	size   int64
	length = runtime.NumCPU() * 64
	sizes  = []int64{
		64,
		512 * 1000,
		64 * 1000 * 1000,
		1 * 1000 * 1000 * 1000,
	}
	fn = []func(b *testing.B){
		func(b *testing.B) {
			makeBytes(size)
			b.SetBytes(size)
			b.ResetTimer()
			for i := b.N; i > 0; i-- {
				rathash.Sum(rBytes, length)
			}
		},
		func(b *testing.B) {
			makeBytes(size)
			b.SetBytes(size)
			b.ResetTimer()
			for i := b.N; i > 0; i-- {
				sha512.Sum512(rBytes)
			}
		},
		func(b *testing.B) {
			makeBytes(size)
			b.SetBytes(size)
			b.ResetTimer()
			for i := b.N; i > 0; i-- {
				blake3.Sum512(rBytes)
			}
		},
	}
)

func makeBytes(size int64) {
	rBytes = make([]byte, size)
	_, err := rand.Read(rBytes)
	if err != nil {
		panic("failed to generate random data")
	}
}

func algBench(alg int) {
	switch alg {
	case 0:
		fmt.Printf("RatHash-%-4g 64B    512K     64M      1G\n", float64(length))
	case 1:
		if runtime.GOARCH == "arm64" {
			fmt.Println("SHA-256      64B    512K     64M      1G")
		} else {
			fmt.Println("SHA-512      64B    512K     64M      1G")
		}
	case 2:
		fmt.Println("BLAKE3-512   64B    512K     64M      1G")
	}
	throughputs, speeds, usages := make([]float64, 4), make([]float64, 4), make([]float64, 4)
	for i := range sizes {
		size = sizes[i]
		var totalHz, polls uint64
		if runtime.GOARCH == "amd64" {
			go func() {
				calltime := gotsc.TSCOverhead()
				for throughputs[i] == 0 {
					tsc1 := gotsc.BenchStart()
					time.Sleep(time.Millisecond)
					tsc2 := gotsc.BenchEnd()
					totalHz += (tsc2 - tsc1 - calltime) * 1000
					polls++
					time.Sleep(time.Millisecond * 19)
				}
			}()
		}
		r := testing.Benchmark(fn[alg])
		throughputs[i] = float64(r.Bytes*int64(r.N)) / r.T.Seconds() /* B/s */
		speeds[i] = float64(totalHz) / float64(polls) / throughputs[i]
		usages[i] = float64(r.AllocedBytesPerOp())
	}

	fmt.Printf("Speed     %7.5g %7.5g %7.5g %7.5g  MB/s\n",
		throughputs[0]/1e6, throughputs[1]/1e6, throughputs[2]/1e6, throughputs[3]/1e6) /* MB/s */
	if speeds[0]+speeds[1]+speeds[2]+speeds[3] > 0 {
		fmt.Printf("          %7.5g %7.5g %7.5g %7.5g  cpb\n",
			speeds[0], speeds[1], speeds[2], speeds[3])
	}
	fmt.Printf("Usage     %7.5g %7.5g %7.5g %7.5g  B/op\n\n",
		usages[0], usages[1], usages[2], usages[3])
}

func main() {
	if length < 256 {
		length = 256
	}
	if runtime.GOARCH == "arm64" {
		fn[1] = func(b *testing.B) {
			makeBytes(size)
			b.SetBytes(size)
			b.ResetTimer()
			for i := b.N; i > 0; i-- {
				sha256.Sum256(rBytes)
			}
		}
	}
	fmt.Printf("Running Statz on %d CPUs!\n\n", runtime.NumCPU())

	t := time.Now()
	ratTest()
	fmt.Println(" ============================================= ")
	algBench(0)
	algBench(1)
	algBench(2)

	fmt.Printf("Finished in %s on %s/%s.\n", time.Since(t).String(), runtime.GOOS, runtime.GOARCH)
}
