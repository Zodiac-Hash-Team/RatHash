package main

import (
	"encoding/base64"
	"fmt"
	"hash/crc64"
	"math/big"
	"os"
	"regexp"
	"strconv"
)

/* N.B.: This project is currently InDev. */
/* This file is the reference Go implementation of the LoveCRC hash function as contrived
by its original author. © 2021 Matthew R Bonnette. The developer thanks The Go Authors
and the developers of its respective libraries, especially those utilized herein. */

/* math/big is stupid: these extension functions make my code cleaner. */
var one = big.NewInt(1)
func exp(x, y, m *big.Int) *big.Int {
	return big.NewInt(0).Exp(x, y, m)
}
func sub(x, y *big.Int) *big.Int {
	return big.NewInt(0).Sub(x, y)
}

/* This is a simple, often—albeit deterministically—inaccurate compositeness test based
on Fermat's little theorem. big.Int.Exp() uses modular exponentiation; this function is
highly optimized. false = composite, true = possibly prime */
func likelyPrime(x *big.Int) bool {
	/* math/big is stupid: this means 2 ** (x - 1) == 1 */
	return exp(big.NewInt(2), sub(x, one), x) == one
}

var message []byte
var length = 192

func hash(msg []byte, ln int) string {
	/* Checks that the requested digest length meets the function's requirements */
	switch ln {
	case 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024:
		break
	default:
		fmt.Printf("Digest length must be one of the following values:\n" +
			"192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024 bits")
		os.Exit(22)
	}

	/* The EXPANSION FUNCTION expands messages by first appending a bit (byte 10000000)
	to the end of them—done to ensure even an input of 0 bytes rendered a unique output—
	and then repeatedly encoding them in base64 until their length in bytes is both at
	least the block length (this is the specified digest length) and divisible by the 64-
	bit word length *if it isn't already*—skipping this effort was deemed not a security
	risk. The word length of 64 was chosen to aid in parallelism and hasten the discovery
	of primes later on in processing step. */
	var block string
	msg = append(msg, 0x80)
	for len(msg) < ln/8 || len(msg)%8 != 0 {
		/* URL encoding because I'm a special snowflake */
		block = base64.URLEncoding.EncodeToString(msg)
	}

	/* The COMPRESSION FUNCTION converts the block into a slice of 64-bit words and
	procedurally trims it down to the required number of items (length/64) by recursively
	subtracting the second-last index by it's last index until it gets to that magic
	size. */
	var wordlist []*big.Int
	splitBlock := regexp.MustCompile(".{8}").Split(block, -1)
	for index := range splitBlock {
		word := splitBlock[index]
		result, _ := strconv.ParseInt(word, 16, 64)
		wordlist[index] = big.NewInt(result)
	}
	for len(wordlist) != ln/64 {
		/* Because the first index is 0 */
		ultimate := len(wordlist) - 1
		penultimate := ultimate - 1
		wordlist[penultimate] = sub(wordlist[penultimate], wordlist[ultimate])
	}

	// PRIMALITY-BASED PROCESSING
	var polys []uint64
	for index := range wordlist {
		word := wordlist[index]
		prime := wordlist[index]
		for likelyPrime(prime) != true {
			prime = sub(prime, one)
		}
		polys[index] = sub(word, prime).Uint64()
	}

	// DIGEST FORMATION
	var splitDigest []uint64
	for index := range polys {
		table := crc64.MakeTable(polys[index])
		splitDigest[index] = crc64.Checksum(msg, table)
	}
	var digest string
	for index := range splitDigest {
		segment := splitDigest[index]
		digest += strconv.FormatUint(segment, 16)
	}
	return digest
}
