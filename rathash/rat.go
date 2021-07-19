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
	var (
		message = msg
		blocks  [][]byte
		group   sync.WaitGroup
		sums    = make([]uint64, ln>>6)
		digest  []byte
	)

	// KEY EXTENSION FUNCTION
	if len(message) < ln>>1 {
		var (
			ceiling = len(primes) - 1
			product = big.NewInt(0).SetBytes(message)
			prime   = big.NewInt(0)
			one     = big.NewInt(1)
		)
		product.Add(product, one) /* Makes input zero-insensitive */
		for i := 1; product.BitLen() < ln<<2 || product.BitLen()&63 != 0; i++ {
			if i > ceiling {
				prime.Add(product, one)
				for prime.ProbablyPrime(1) != true {
					prime.Add(product, one)
				}
				product.Mul(product, prime)
				continue
			}
			prime.SetUint64(primes[i])
			product.Mul(product, prime)
		}
		message = product.Bytes()
	}
	/*file, _ := os.Create("same as 0B")
	_, _ = file.Write(message)*/

	// MESSAGE DIVISION
	for len(message)&(ln>>6-1) != 0 {
		message = append(message, 0b01011101)
	}
	bSize := len(message) / (ln >> 6)
	for len(message) != 0 {
		blocks = append(blocks, message[:bSize])
		message = message[bSize:]
	}
	for i := range blocks {
		/* Supplemental expansion */
		for len(blocks[i])&7 != 0 {
			blocks[i] = append(blocks[i], 0b01101101)
		}
	}

	// DIFFUSION FUNCTION
	for i := range blocks {
		group.Add(1)
		go func(i int) {
			/* Converts each block of bytes into a block of uint64's */
			block := make([]uint64, bSize>>3)
			for i2 := range block {
				/* Little-endian */
				block[i2] = *(*uint64)(unsafe.Pointer(&blocks[i][i2<<3]))
			}

			/* In descending order and starting with the penultimate word, assign each word with the
			result of itself ANDed by its predecessor. */
			ultima := len(block) - 1
			penult := ultima - 1
			for penult != -1 {
				block[penult] &= block[ultima]
				ultima--
				penult--
			}
			block[len(block)-1] &= block[0]
			/* In descending order and starting with the penultimate word, assign each word with the
			result of itself NOT-ORred by its predecessor. */
			ultima = len(block) - 1
			for ultima != -1 {
				block[ultima] *= 0xfffffffb
				ultima--
			}
			/* In descending order and starting with the penultimate word, assign each word with the
			result of itself XORred by its predecessor bit-rotated by 1 to the left. */
			ultima = len(block) - 1
			penult = ultima - 1
			for penult != -1 {
				block[penult] ^= bits.RotateLeft64(block[ultima], ultima)
				ultima--
				penult--
			}
			block[len(block)-1] ^= block[0]
			/* Mark the 64-bit word at index 0 as the polynomial for this block. */
			sums[i] = block[0]
			group.Done()
		}(i)
	}
	group.Wait()

	// COMBINATOR FUNCTION
	/* Making each block depend on the contents of each other */
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

	// DIGEST FORMATION
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
