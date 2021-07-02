package lovecrc

import (
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"math/big"
	"strconv"
)

// N.B.: This project is currently InDev. © 2021 Matthew R Bonnette
/* This file is the reference Go implementation of the LoveCRC hash function as contrived
by its original author. LoveCRC's developer thanks The Go Authors and the developers of
its respective libraries, especially those utilized herein. */

func Hash(msg []byte, ln int) string {
	/* Checks that the requested digest length meets the function's requirements */
	switch ln {
	case 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024:
		break
	default:
		panic("invalid input: digest length")
	}

	// EXPANSION FUNCTION
	msg = append(msg, 0x80)
	encoded := msg
	for len(encoded) < ln/8 || len(encoded)%4 != 0 {
		encoded = []byte(base64.StdEncoding.EncodeToString(encoded))
	}
	expanded := string(encoded)
	fmt.Printf("%d bytes expanded\n", len(expanded)) // Debugging

	// COMPRESSION FUNCTION
	var split []string
	for len(expanded) != 0 {
		split = append(split, expanded[:4])
		expanded = expanded[4:]
	}
	block := make([]uint32, len(split))
	for dex := range split {
		word, _ := strconv.ParseUint(fmt.Sprintf("%x", split[dex]), 16, 32)
		block[dex] = uint32(word)
	}
	/* Because the first index is 0 */
	ultima := len(block) - 1
	penult := ultima - 1
	for penult != 0 {
		block[penult] = block[penult] - block[ultima]
		ultima--
		penult--
	}
	block = block[:ln/32]

	// PRIMALITY-BASED PROCESSING
	for dex := range block {
		word := int64(block[dex])
		for big.NewInt(word).ProbablyPrime(1) != true {
			word--
		}
		block[dex] = uint32(word)
	}
	// Debugging
	fmt.Printf("polys:\n")
	for dex := range block {
		poly := block[dex]
		fmt.Printf("%x ", poly)
	}
	fmt.Printf("\n")

	// DIGEST FORMATION
	for dex := range block {
		table := crc32.MakeTable(block[dex])
		block[dex] = crc32.Checksum(msg, table)
	}
	var digest string
	for dex := range block {
		digest += fmt.Sprintf("%x", block[dex])
	}
	return digest
}
