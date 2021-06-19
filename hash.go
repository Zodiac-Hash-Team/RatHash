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

/* This is a simple, often—albeit deterministically—inaccurate compositeness test based
on Fermat's little theorem. big.Int.Exp() uses modular exponentiation; this function is
highly optimized. false = composite, true = likely prime */
func likelyPrime(x *big.Int) bool {
	/* math/big is stupid: this means 2 ** (x - 1) == 1 */
	return one.Exp(big.NewInt(2), one.Sub(x, one), x) == one
}

var message []byte
var length = 192
var one = big.NewInt(1)

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
	var expanded string
	msg = append(msg, 0x80)
	for len(msg) < ln/8 || len(msg)%8 != 0 {
		/* URL encoding because I'm a special snowflake */
		expanded = base64.URLEncoding.EncodeToString(msg)
	}

	/* The COMPRESSION FUNCTION converts the block into a slice of 64-bit words and
	procedurally trims it down to the required number of items (length/64) by recursively
	subtracting the second-last index by it's last index until it gets to that magic
	size. */
	var block []*big.Int
	splitBlock := regexp.MustCompile(".{8}").Split(expanded, -1)
	for index := range splitBlock {
		word := splitBlock[index]
		result, _ := strconv.ParseInt(word, 16, 64)
		block[index] = big.NewInt(result)
	}
	for len(block) != ln/64 {
		/* Because the first index is 0 */
		ultima := len(block) - 1
		penult := ultima - 1
		block[penult] = one.Sub(block[penult], block[ultima])
		block = block[:len(block) - 2]
	}

	// PRIMALITY-BASED PROCESSING
	var polys []uint64
	for index := range block {
		word := block[index]
		prime := block[index]
		for likelyPrime(prime) != true {
			prime = one.Sub(prime, one)
		}
		polys[index] = one.Sub(word, prime).Uint64()
	}

	// DIGEST FORMATION
	var sections []uint64
	for index := range polys {
		table := crc64.MakeTable(polys[index])
		sections[index] = crc64.Checksum(msg, table)
	}
	var digest string
	for index := range sections {
		segment := sections[index]
		digest += strconv.FormatUint(segment, 16)
	}
	return digest
}
