package main

import (
	"crypto/sha256"
	"crypto/sha512"
	. "fmt"
	"github.com/dterei/gotsc"
	"github.com/p7r0x7/rathash"
	"github.com/zeebo/blake3"
	"math/bits"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.

var sizes = []int{64, 512 << 10, 64 << 20, 1 << 30}
var bytes, sha2, cpb, calltime = []byte(nil), "with sha512", "w/o cpb", gotsc.TSCOverhead()
var fn = []func(b *testing.B){
	func(b *testing.B) {
		d, _ := rathash.NewHash([32]byte{}, nil)
		b.SetBytes(int64(len(bytes)))
		b.ResetTimer()
		for i := b.N; i > 0; i-- {
			d.Write(bytes)
			d.Sum(bytes[:len(bytes)-32])
		}
		b.StopTimer()
		d.Reset()
	},
	func(b *testing.B) {
		b.SetBytes(int64(len(bytes)))
		b.ResetTimer()
		for i := b.N; i > 0; i-- {
			sha256.Sum256(bytes)
		}
	},
	func(b *testing.B) {
		b.SetBytes(int64(len(bytes)))
		b.ResetTimer()
		for i := b.N; i > 0; i-- {
			sha512.Sum512(bytes)
		}
	},
	func(b *testing.B) {
		b.SetBytes(int64(len(bytes)))
		b.ResetTimer()
		for i := b.N; i > 0; i-- {
			blake3.Sum256(bytes)
		}
	},
}

func benchAlg(alg int) {
	switch alg {
	case 0:
		Println("github.com/p7r0x7/rathash")
	case 1:
		Println("crypto/sha256")
	case 2:
		Println("crypto/sha512")
	case 3:
		Println("github.com/zeebo/blake3")
	}
	throughputs, speeds, usages :=
		make([]float64, len(sizes)), make([]float64, len(sizes)), make([]float64, len(sizes))

	for i, v := range sizes {
		bytes = make([]byte, v)

		totalHz, polls, mut := uint64(0), uint64(0), &sync.Mutex{}
		if cpb == "with cpb" {
			go func() {
				for {
					tsc1 := gotsc.BenchStart()
					time.Sleep(time.Millisecond)
					tsc2 := gotsc.BenchEnd()

					mut.Lock()
					totalHz += (tsc2 - tsc1 - calltime) * 1000
					polls++
					mut.Unlock()

					time.Sleep(time.Millisecond * 9)
				}
			}()
		}
		r := testing.Benchmark(fn[alg])
		mut.Lock()

		throughputs[i] = float64(r.Bytes*int64(r.N)) / r.T.Seconds() /* B/s */
		speeds[i] = float64(totalHz) / float64(polls) / throughputs[i]
		throughputs[i] /= 1e6 /* MB/s */
		usages[i] = float64(r.AllocedBytesPerOp())
	}

	Println("Speed " + fmtFloats(throughputs...) + "   MB/s")
	if cpb == "with cpb" {
		Println("      " + fmtFloats(speeds...) + "   cpb")
	}
	Println("Usage " + fmtFloats(usages...) + "   B/op\n")
}

func fmtFloats(f ...float64) string {
	var str, style string
	for _, v := range f {
		switch whole := float64(int64(v)) == v; {
		case v > 1e8 || (v < 1e-6 && !whole):
			style = "%8.3g"
		case v <= 1e1 && !whole:
			style = "%8.6f"
		case v <= 1e2 && !whole:
			style = "%8.5f"
		case v <= 1e3 && !whole:
			style = "%8.4f"
		case v <= 1e4 && !whole:
			style = "%8.3f"
		case v <= 1e5 && !whole:
			style = "%8.2f"
		case v <= 1e6 && !whole:
			style = "%8.1f"
		default:
			style = "%8.f"
		}
		str += "  " + Sprintf(style, v)
	}
	return str
}

func main() {
	if runtime.GOARCH == "arm64" || bits.UintSize == 32 {
		sha2 = "with sha256"
	} else if calltime > 0 {
		cpb = "with cpb"
	}

	Printf("Running Statz on %d CPUs!\n%s/%s: %s, %s\n\n"+
		"           64B      512K       64M       1G\n",
		runtime.NumCPU(), runtime.GOOS, runtime.GOARCH, sha2, cpb)

	t := time.Now()
	benchAlg(0)
	if sha2 == "with sha256" {
		benchAlg(1)
	} else {
		benchAlg(2)
	}
	benchAlg(3)

	Println("Finished in " + time.Since(t).Truncate(time.Millisecond).String() + ".")
}
