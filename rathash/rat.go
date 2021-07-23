package rathash

import (
	"math/big"
	"math/bits"
	"sync"
	"unsafe"
)

// N.B.: This project is currently InDev.
// Copyright © 2021 Matthew R Bonnette. Openly-licensed under a BSD-3-Clause license.
/* This file is the reference Go implementation of the RatHash function as contrived by its original
author. RatHash's developer thanks The Go Authors and the developers of any third-party libraries
utilized in this project. */

func Sum(msg []byte, ln int) []byte {
	/* Checks that the requested digest length meets the function's requirements */
	if ln < 256 || ln&63 != 0 {
		panic("invalid input: digest length")
	}
	const phiE19 uint64 = 16180339887498948482
	var (
		mSize = len(msg)
		/* Initializes to zero, but *may* be modified prior to compression */
		sums   = make([]uint64, ln>>6)
		group  sync.WaitGroup
		digest []byte
	)

	// EXTENSION *OR* INITIALIZATION
	const ceiling = len(primes) - 1
	product, prime, two := big.NewInt(0), big.NewInt(0), big.NewInt(2)
	if mSize < ln>>1 {
		product.SetBytes(msg)
		/* Makes input zero-insensitive */
		product.Add(product, big.NewInt(0).SetUint64(phiE19))
		/* Skips 2, because 2 bad */
		for i := 1; product.BitLen() < ln<<2 || product.BitLen()&63 != 0; i++ {
			if i > ceiling {
				prime.Add(prime, two)
				for prime.ProbablyPrime(1) != true {
					prime.Add(prime, two)
				}
				product.Mul(product, prime)
				continue
			}
			prime.SetUint64(primes[i])
			product.Mul(product, prime)
		}
		msg = product.Bytes() /* Doesn't allocate memory to store `msg` until this point */
	} else {
		product.SetUint64(phiE19)
		/* Skips 2, because 2 bad */
		for i := 1; product.BitLen() < ln; i++ {
			if i > ceiling {
				prime.Add(prime, two)
				for prime.ProbablyPrime(1) != true {
					prime.Add(prime, two)
				}
				product.Mul(product, prime)
				continue
			}
			prime.SetUint64(primes[i])
			product.Mul(product, prime)
		}
		tmp := product.Bytes()[:ln>>3] /* Truncates to the correct byte count */
		for i := range sums {
			/* Little-endian */
			sums[i] = *(*uint64)(unsafe.Pointer(&tmp[i<<3]))
		}
	}

	// PARALLEL COMPRESSION
	mSize = len(msg)
	bSize := (mSize + mSize%(ln>>6)) / (ln >> 6) /* len(msg)/(ln/64) rounded up */
	rem := bSize & 7
	for i := ln>>6 - 1; i >= 0; i-- {
		group.Add(1)
		go func(i int) {
			var val, pop, sum uint64

			switch rem {
			case 7:
				val = bits.Reverse64(uint64(msg[bSize*(i+1)-8])<<56) ^ phiE19 + sums[i]
			case 6:
				val = bits.Reverse64(
					uint64(msg[bSize*(i+1)-8])<<56|
						uint64(msg[bSize*(i+1)-7])<<48) ^ phiE19 + sums[i]
			case 5:
				val = bits.Reverse64(
					uint64(msg[bSize*(i+1)-8])<<56|
						uint64(msg[bSize*(i+1)-7])<<48|
						uint64(msg[bSize*(i+1)-6])<<40) ^ phiE19 + sums[i]
			case 4:
				val = bits.Reverse64(
					uint64(msg[bSize*(i+1)-8])<<56|
						uint64(msg[bSize*(i+1)-7])<<48|
						uint64(msg[bSize*(i+1)-6])<<40|
						uint64(msg[bSize*(i+1)-5])<<32) ^ phiE19 + sums[i]
			case 3:
				val = bits.Reverse64(
					uint64(msg[bSize*(i+1)-8])<<56|
						uint64(msg[bSize*(i+1)-7])<<48|
						uint64(msg[bSize*(i+1)-6])<<40|
						uint64(msg[bSize*(i+1)-5])<<32|
						uint64(msg[bSize*(i+1)-4])<<24) ^ phiE19 + sums[i]
			case 2:
				val = bits.Reverse64(
					uint64(msg[bSize*(i+1)-8])<<56|
						uint64(msg[bSize*(i+1)-7])<<48|
						uint64(msg[bSize*(i+1)-6])<<40|
						uint64(msg[bSize*(i+1)-5])<<32|
						uint64(msg[bSize*(i+1)-4])<<24|
						uint64(msg[bSize*(i+1)-3])<<16) ^ phiE19 + sums[i]
			case 1:
				val = bits.Reverse64(
					uint64(msg[bSize*(i+1)-8])<<56|
						uint64(msg[bSize*(i+1)-7])<<48|
						uint64(msg[bSize*(i+1)-6])<<40|
						uint64(msg[bSize*(i+1)-5])<<32|
						uint64(msg[bSize*(i+1)-4])<<24|
						uint64(msg[bSize*(i+1)-3])<<16|
						uint64(msg[bSize*(i+1)-2])<<8) ^ phiE19 + sums[i]
			default:
				val = *(*uint64)(unsafe.Pointer(&msg[bSize*(i+1)-7])) + sums[i]
			}
			pop = uint64(bits.OnesCount64(val))
			sum ^= pop * pop * val

			for i2 := bSize>>3 - 2; i2 >= 0; i2-- {
				val = *(*uint64)(unsafe.Pointer(&msg[i*bSize+i2<<3])) + sums[i]
				pop = uint64(bits.OnesCount64(val))
				sum ^= pop * pop * val
			}
			sums[i] = sum
			group.Done()
		}(i)
	}
	group.Wait()

	// COMBINATION & DIGEST FORMATION
	ultima := ln>>6 - 1
	penult := ultima - 1
	for penult != -1 {
		sums[penult] ^= sums[ultima]
		ultima--
		penult--
	}
	sums[ln>>6-1] ^= sums[0]
	ultima = ln>>6 - 1
	penult = ultima - 1
	for penult != -1 {
		sums[penult] ^= sums[ultima]
		ultima--
		penult--
	}
	sums[ln>>6-1] ^= sums[0]

	digest = make([]byte, ln>>3)
	for i := range sums {
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
