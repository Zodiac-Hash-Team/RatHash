package main

import (
	"encoding/base64"
	"fmt"
	"hash/crc64"
	"math/big"
	"strconv"
)

/* N.B.: This project is currently InDev. */
/* This file is the reference Go implementation of the LoveCRC hash function as contrived
by its original author. © 2021 Matthew R Bonnette. The developer thanks The Go Authors
and the developers of its respective libraries, especially those utilized herein. */

var message []byte
var length = 192

func hash(msg []byte, ln int) string {
	/* Checks that the requested digest length meets the function's requirements */
	switch ln {
	case 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024:
		break
	default:
		panic("invalid input: digest length")
	}

	/* The EXPANSION FUNCTION expands messages by first appending a bit (byte 10000000)
	to the end of them—done to ensure even an input of 0 bytes rendered a unique output—
	and then repeatedly encoding them in base64 until their length in bytes is both at
	least the block length (this is the specified digest length) and divisible by the 64-
	bit word length *if it isn't already*—skipping this effort was deemed not a security
	risk. The word length of 64 was chosen to aid in parallelism and hasten the discovery
	of primes later on in processing step. */
	msg = append(msg, 0x80)
	encoded := msg
	for len(encoded) < ln/8 || len(encoded)%8 != 0 {
		/* URL encoding because I'm a special snowflake */
		encoded = []byte(base64.URLEncoding.EncodeToString(encoded))
	}
	expanded := string(encoded)
	fmt.Printf("    %d bytes expanded\n", len(expanded)) // Debugging

	/* The COMPRESSION FUNCTION converts the block into a slice of 64-bit words and
	procedurally trims it down to the required number of items (length/64) by recursively
	subtracting the second-last index by it's last index until it gets to that magic
	size. */
	var split []string
	for len(expanded) != 0 {
		split = append(split, expanded[:8])
		expanded = expanded[8:]
	}
	for dex := range split {
		word := split[dex]
		split[dex] = fmt.Sprintf("%x", word)
	}
	block := make([]int64, len(split))
	for dex := range split {
		word := split[dex]
		block[dex], _ = strconv.ParseInt(word, 16, 64)
	}
	for len(block) != ln/64 {
		/* Because the first index is 0 */
		ultima := len(block) - 1
		penult := ultima - 1
		block[penult] = block[penult] ^ block[ultima]
		block = block[:ultima]
	}
	fmt.Printf("    block: %x %x %x\n", block[0], block[1], block[2]) // Debugging

	// PRIMALITY-BASED PROCESSING
	polys := make([]uint64, ln/64)
	for dex := range block {
		word := block[dex]
		prime := word
		for big.NewInt(prime).ProbablyPrime(4) != true {
			prime--
		}
		polys[dex] = uint64(word^prime) ^ 0xffffffffffffffff
	}
	fmt.Printf("    polys: %x %x %x\n", polys[0], polys[1], polys[2]) // Debugging

	// DIGEST FORMATION
	sections := make([]uint64, ln/64)
	for dex := range polys {
		table := crc64.MakeTable(polys[dex])
		sections[dex] = crc64.Checksum(msg, table)
	}
	var digest string
	for index := range sections {
		segment := sections[index]
		digest += fmt.Sprintf("%x", segment)
	}
	return digest
}
