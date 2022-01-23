package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/dterei/gotsc"
	"github.com/p7r0x7/rathash/api"
	"github.com/zeebo/blake3"
	"math/rand"
	"runtime"
	"testing"
	"time"
)

// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.

var (
	size  int64
	sizes = []int64{
		64,
		512 * 1000,
		64 * 1000 * 1000,
		1 * 1000 * 1000 * 1000,
	}
	sha2 = "with sha512"
	cpb  = "w/o cpb"

	fn = []func(b *testing.B){
		func(b *testing.B) {
			bytes := makeBytes(size)
			b.SetBytes(size)
			b.ResetTimer()
			for i := b.N; i > 0; i-- {
				api.Sum(bytes, 256)
			}
		},
		func(b *testing.B) {
			bytes := makeBytes(size)
			b.SetBytes(size)
			b.ResetTimer()
			for i := b.N; i > 0; i-- {
				sha256.Sum256(bytes)
			}
		},
		func(b *testing.B) {
			bytes := makeBytes(size)
			b.SetBytes(size)
			b.ResetTimer()
			for i := b.N; i > 0; i-- {
				sha512.Sum512(bytes)
			}
		},
		func(b *testing.B) {
			bytes := makeBytes(size)
			b.SetBytes(size)
			b.ResetTimer()
			for i := b.N; i > 0; i-- {
				blake3.Sum256(bytes)
			}
		},
	}
)

func init() {
	rand.Seed(time.Now().UnixNano())
	if runtime.GOARCH == "arm64" {
		sha2 = "with sha256"
	} else if runtime.GOARCH == "amd64" {
		cpb = "with cpb"
	}
}

func makeBytes(size int64) []byte {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		panic("failed to generate random data")
	}
	return bytes
}

func benchAlg(alg int) {
	switch alg {
	case 0:
		fmt.Println("github.com/p7r0x7/rathash/api")
	case 1:
		fmt.Println("crypto/sha256")
	case 2:
		fmt.Println("crypto/sha512")
	case 3:
		fmt.Println("github.com/zeebo/blake3")
	}
	throughputs, speeds, usages := make([]float64, 4), make([]float64, 4), make([]float64, 4)
	for i := range sizes {
		size = sizes[i]
		var totalHz, polls uint64
		if cpb == "with cpb" {
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
	t := time.Now()
	fmt.Printf("Running Statz on %d CPUs!\n%s/%s: %s, %s\n\n",
		runtime.NumCPU(), runtime.GOOS, runtime.GOARCH, sha2, cpb)

	fmt.Printf("             64B    512K     64M      1G\n\n")

	benchAlg(0)
	if sha2 == "with sha256" {
		benchAlg(1)
	} else {
		benchAlg(2)
	}
	benchAlg(3)

	fmt.Printf("Finished in %s.\n", time.Since(t).String())
}
