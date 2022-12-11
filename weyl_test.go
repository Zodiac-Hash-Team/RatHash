package rathash

import (
	bytes2 "bytes"
	"compress/flate"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"
	"unsafe"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func TestWeylSeeds_Roots(t *testing.T) {
	t.Parallel()
	sequence := make([]uint64, wordsPerBlock*rounds)
	bytes := (*[bytesPerBlock * rounds]byte)(unsafe.Pointer(&sequence[0]))[:]
	two64, float, conv := &big.Float{}, &big.Float{}, &big.Float{}
	two64.SetString("1p64") /* 1*2**64 */
	float.SetPrec(128)

	var b = &bytes2.Buffer{}
	w, _ := flate.NewWriter(b, flate.BestCompression)

	var best int
	for i := uint64(2); i < 1<<32; i++ {
		trunc, _ := float.SetUint64(i).Sqrt(float).Uint64()
		float.Sub(float, conv.SetUint64(trunc)).Mul(two64, float)
		seed, _ := float.Uint64()
		if seed&1 == 0 {
			continue
		}

		var next uint64
		for i2 := range sequence {
			next += seed
			sequence[i2] = next
		}
		_, _ = w.Write(bytes)
		if size := b.Len(); size > best {
			best = size
			fmt.Printf("New best: sqrt(%d)  %x  ratio: %v\n", i, seed,
				float64(bytesPerBlock*rounds)/float64(size))
		}
		b.Reset()
		w.Reset(b)
	}
}

func TestWeylSeeds_Random(t *testing.T) {
	t.Parallel()
	sequence := make([]uint64, wordsPerBlock*rounds<<2)
	bytes := (*[bytesPerBlock * rounds]byte)(unsafe.Pointer(&sequence[0]))[:]

	var b = &bytes2.Buffer{}
	w, _ := flate.NewWriter(b, flate.HuffmanOnly)

	var best int
	for i := 0; i < 1<<32; i++ {
		seed := rand.Uint64() | 1
		var next uint64
		for i2 := range sequence {
			next += seed
			sequence[i2] = next
		}
		_, _ = w.Write(bytes)
		if size := b.Len(); size > best {
			best = size
			fmt.Printf("New best:  %x  ratio: %v\n", seed,
				float64(bytesPerBlock*rounds)/float64(size))
		}
		b.Reset()
		w.Reset(b)
	}
}

func TestWeylSeeds_Sequential(t *testing.T) {
	t.Parallel()
	sequence := make([]uint64, wordsPerBlock*rounds)
	bytes := (*[bytesPerBlock * rounds]byte)(unsafe.Pointer(&sequence[0]))[:]

	var b = &bytes2.Buffer{}
	w, _ := flate.NewWriter(b, flate.HuffmanOnly)

	var best int
	for seed := uint64(1); seed < 1<<32; seed += 2 {
		var next uint64
		for i2 := range sequence {
			next += seed
			sequence[i2] = next
		}
		_, _ = w.Write(bytes)
		if size := b.Len(); size > best {
			best = size
			fmt.Printf("New best:  %x  ratio: %v\n", seed,
				float64(bytesPerBlock*rounds)/float64(size))
		}
		b.Reset()
		w.Reset(b)
	}
}
