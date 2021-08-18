package rathash

import (
	"math/big"
	"math/bits"
	"sync"
	"unsafe"
)

// N.B.: This project is currently InDev.
// Copyright © 2021 Matthew R Bonnette. Licensed under a BSD-3-Clause license.
// This file is the reference Go implementation of the RatHash function as contrived by its original
// author. RatHash's developer thanks The Go Authors and the developers of any third-party libraries
// utilized in this project.

/*
var (
	count int
	rngln int
	size  int
	wall  time.Time
	state []byte
)

func RNGInit() {
	rngln = runtime.NumCPU() * 64
	if rngln < 256 {
		rngln = 256
	}
	count, size, state = -1, rngln>>3, make([]byte, rngln<<2)
	for i := rngln - 1; i >= 0; i-- {
		state[i] = byte(time.Since(wall).Nanoseconds())
	}
	for i := 32 - 1; i >= 0; i-- {
		tmp := halfsum(state, rngln)
		for i2 := size - 1; i2 >= 0; i2-- {
			state[size*i+i2] = tmp[i2]
		}
	}
}

func RNGNext() uint64 {
	count = (count + 1) % size << 2
	if count%size>>3 == 0 {
		for i := 32 - 1; i >= 0; i-- {
			state[size*i] ^= byte(time.Since(wall).Nanoseconds())
		}
		tmp := halfsum(state, rngln)
		for i := size - 1; i >= 0; i-- {
			state[count<<3+i] = tmp[i]
		}
	}
	return *(*uint64)(unsafe.Pointer(&state[count<<3]))
}
*/

func Sum(msg, mac []byte, ln int) []byte {
	var sum1, sum2 []byte
	if mac != nil {
		/* MACs called to the function must be at least the size of the output. */
		if len(mac) < ln>>3 {
			panic("invalid input: MAC length too short")
		} else {
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				sum1 = halfsum(msg, ln)
				wg.Done()
			}()
			go func() {
				sum2 = halfsum(mac, ln)
				wg.Done()
			}()
			wg.Wait()
		}
	} else {
		sum1 = halfsum(msg, ln)
		sum2 = halfsum(sum1, ln)
	}
	for i := ln>>3 - 1; i >= 0; i-- {
		sum1[i] ^= sum2[i]
	}
	return sum1
}

func halfsum(msg []byte, ln int) []byte {
	/* Checks that the requested digest length meets the function's requirements */
	if ln < 256 || ln&63 != 0 {
		panic("invalid input: digest length")
	}
	const phiE19 uint64 = 16180339887498948482 /* In decimal for easy verification */
	/* Initializes to zero, but *may* be modified prior to compression */
	sums := make([]uint64, ln>>6)
	mSize := len(msg)

	// EXTENSION *OR* INITIALIZATION
	const ceiling = len(primes) - 1
	if mSize < ln>>1 {
		/* For small inputs, the algorithm is made sensitive to length-extension and insensitive to
		all-zero inputs by prepending `msg` with the bytes of phiE19. They are in hexadecimel for
		easy verification. */
		product := big.NewInt(0).SetBytes(
			append([]byte{0xe0, 0x8c, 0x1d, 0x66, 0x8b, 0x75, 0x6f, 0x82}, msg...))
		prime, length := big.NewInt(0), product.BitLen()
		for i := 1; (length < ln<<2 || length&63 != 0) && i <= ceiling; i++ {
			length = product.Mul(product, prime.SetUint64(primes[i])).BitLen()
		}
		for two := big.NewInt(2); length < ln<<2 || length&63 != 0; {
			for prime.Add(prime, two).ProbablyPrime(1) == false {
			}
			length = product.Mul(product, prime).BitLen()
		}
		msg = product.Bytes()
		mSize = len(msg) /* Updates mSize */
	} else {
		product, prime, length := big.NewInt(0).SetUint64(phiE19), big.NewInt(0), 64
		for i := 1; length < ln && i <= ceiling; i++ {
			length = product.Mul(product, prime.SetUint64(primes[i])).BitLen()
		}
		for two := big.NewInt(2); length < ln; {
			for prime.Add(prime, two).ProbablyPrime(1) == false {
			}
			length = product.Mul(product, prime).BitLen()
		}
		tmp := product.Bytes()[:ln>>3] /* Truncates to the correct byte count */
		for i := range sums {
			/* Little-endian byte order */
			sums[i] = *(*uint64)(unsafe.Pointer(&tmp[i<<3]))
		}
	}

	// PARALLEL COMPRESSION
	var wg sync.WaitGroup
	const fermat5, loMask, hiMask uint64 = 4294967297, 0xffffffff00000000, 0x00000000ffffffff
	bSize := (mSize / (ln >> 3)) << 3
	mRem := mSize - (ln >> 6 * bSize)
	rem := mRem & 7

	for i := ln>>6 - 1; i >= 0; i-- {
		wg.Add(1)
		go func(i int) {
			var word, hi, lo, weyl uint64
			bRem, sum := mRem/8, sums[i]

			if i == ln>>6-1 {
				switch rem {
				case 7:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56) ^ phiE19
				case 6:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48) ^ phiE19
				case 5:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40) ^ phiE19
				case 4:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40|
							uint64(msg[bSize*(i+1)-4])<<32) ^ phiE19
				case 3:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40|
							uint64(msg[bSize*(i+1)-4])<<32|
							uint64(msg[bSize*(i+1)-3])<<24) ^ phiE19
				case 2:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40|
							uint64(msg[bSize*(i+1)-4])<<32|
							uint64(msg[bSize*(i+1)-3])<<24|
							uint64(msg[bSize*(i+1)-2])<<16) ^ phiE19
				case 1:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40|
							uint64(msg[bSize*(i+1)-4])<<32|
							uint64(msg[bSize*(i+1)-3])<<24|
							uint64(msg[bSize*(i+1)-2])<<16|
							uint64(msg[bSize*(i+1)-1])<<8) ^ phiE19
				default:
					/* Little-endian byte order */
					word = *(*uint64)(unsafe.Pointer(&msg[bSize*(i+1)-7]))
				}
			} else {
				/* Little-endian byte order */
				word = *(*uint64)(unsafe.Pointer(&msg[bSize*(i+1)-7]))
				bRem = 0
			}
			for i2 := bits.OnesCount64(word) >> 1; i2 > 0; i2-- {
				hi, lo = bits.Mul64(word, word)
				word = (lo&loMask | hi&hiMask) + weyl
				weyl += fermat5
			}
			sum ^= word

			for i2 := bSize>>3 + bRem - 2; i2 >= 0; i2-- {
				word = *(*uint64)(unsafe.Pointer(&msg[i*bSize+i2<<3]))
				for i3 := bits.OnesCount64(word) >> 1; i3 > 0; i3-- {
					hi, lo = bits.Mul64(word, word)
					word = (lo&loMask | hi&hiMask) + weyl
					weyl += fermat5
				}
				sum ^= word
			}
			sums[i] = sum
			wg.Done()
		}(i)
	}
	wg.Wait()

	// HALF DIGEST FORMATION
	digest := make([]byte, ln>>3)
	for i := ln>>6 - 1; i >= 0; i-- {
		digest[0+i<<3] = byte(sums[i] >> 56)
		digest[1+i<<3] = byte(sums[i] >> 48)
		digest[2+i<<3] = byte(sums[i] >> 40)
		digest[3+i<<3] = byte(sums[i] >> 32)
		digest[4+i<<3] = byte(sums[i] >> 24)
		digest[5+i<<3] = byte(sums[i] >> 16)
		digest[6+i<<3] = byte(sums[i] >> 8)
		digest[7+i<<3] = byte(sums[i])
	}

	return digest
}
