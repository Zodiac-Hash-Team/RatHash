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
	if ln < 256 || ln%64 != 0 {
		panic("invalid input: digest length")
	}
	var (
		message = msg
		blocks  [][]byte
		group   sync.WaitGroup
		digest  []byte
	)

	// KEY STRETCHING
	if len(message) < ln/2 {
		ceiling := len(primes) - 1
		product, prime, one := big.NewInt(0).SetBytes(message), big.NewInt(0), big.NewInt(1)
		product.Add(product, one) /* Makes input zero-insensitive */
		for i := 1; product.BitLen() < ln*4; i++ {
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

	// MESSAGE DIVISION
	for len(message)%(ln/64) != 0 {
		message = append(message, 0x01)
	}
	bSize := len(message) / (ln / 64)
	for len(message) != 0 {
		blocks = append(blocks, message[:bSize])
		message = message[bSize:]
	}
	for i := range blocks {
		/* Supplemental expansion */
		for len(blocks[i])%8 != 0 {
			blocks[i] = append(blocks[i], 0x01)
		}
	}

	// DIFFUSION FUNCTION
	polys := make([]uint64, ln/64)
	for i := range blocks {
		group.Add(1)
		go func(i int) {
			/* Converts each block of bytes into a block of uint64's */
			block := make([]uint64, bSize/8)
			for i2 := range block {
				/* Little-endian */
				block[i2] = *(*uint64)(unsafe.Pointer(&blocks[i][i2*8]))
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
			polys[i] = block[0]
			group.Done()
		}(i)
	}
	group.Wait()

	// COMBINATOR FUNCTION
	/* Making each block depend on the contents of each other */
	ultima := ln/64 - 1
	penult := ultima - 1
	for penult != -1 {
		polys[penult] ^= polys[ultima]
		ultima--
		penult--
	}
	polys[ln/64-1] ^= polys[0]
	ultima = ln/64 - 1
	penult = ultima - 1
	for penult != -1 {
		polys[penult] ^= polys[ultima]
		ultima--
		penult--
	}
	polys[ln/64-1] ^= polys[0]

	// DIGEST FORMATION
	digest = make([]byte, ln/8)
	for i := range polys {
		digest[0+i*8] = byte(polys[i] >> 56)
		digest[1+i*8] = byte(polys[i] >> 48)
		digest[2+i*8] = byte(polys[i] >> 40)
		digest[3+i*8] = byte(polys[i] >> 32)
		digest[4+i*8] = byte(polys[i] >> 24)
		digest[5+i*8] = byte(polys[i] >> 16)
		digest[6+i*8] = byte(polys[i] >> 8)
		digest[7+i*8] = byte(polys[i])
	}

	return digest
}
