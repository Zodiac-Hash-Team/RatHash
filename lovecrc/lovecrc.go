package lovecrc

import (
	"encoding/base64"
	"fmt"
	"hash/crc64"
	"strconv"
)

/* N.B.: This project is currently InDev. */
/* This file is the reference Go implementation of the LoveCRC hash function as contrived
by its original author. © 2021 Matthew R Bonnette. The developer thanks The Go Authors
and the developers of its respective libraries, especially those utilized herein. */

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
	for len(encoded) < ln/8 || len(encoded)%2 != 0 {
		encoded = []byte(base64.StdEncoding.EncodeToString(encoded))
	}
	expanded := string(encoded)
	fmt.Printf("%d bytes expanded\n", len(expanded)) // Debugging

	// COMPRESSION FUNCTION
	var split []string
	for len(expanded) != 0 {
		split = append(split, expanded[:2])
		expanded = expanded[2:]
	}
	for dex := range split {
		split[dex] = fmt.Sprintf("%x", split[dex])
	}
	block := make([]uint16, len(split))
	for dex := range split {
		tmp, _ := strconv.ParseUint(split[dex], 16, 16)
		block[dex] = uint16(tmp)
	}
	/* Because the first index is 0 */
	ultima := len(block) - 1
	penult := ultima - 1
	for penult != 0 {
		block[penult] = block[penult] - block[ultima]
		ultima--
		penult--
	}
	block = block[:ln/16]

	// PRIMALITY-BASED PROCESSING
	for dex := range block {
		index := 0
		for primes[index] > block[dex] {
			index++
		}
		block[dex] = primes[index]
	}

	// DIGEST FORMATION
	polys := make([]uint64, ln/64)
	for dex := range polys {
		polys[dex] =
			uint64(block[0+dex*4])<<48 +
				uint64(block[1+dex*4])<<32 +
				uint64(block[2+dex*4])<<16 +
				uint64(block[3+dex*4])
	}
	// Debugging
	fmt.Printf("polys:\n")
	for dex := range polys {
		poly := polys[dex]
		fmt.Printf("%x ", poly)
	}
	fmt.Printf("\n")

	for dex := range polys {
		table := crc64.MakeTable(polys[dex])
		polys[dex] = crc64.Checksum(msg, table)
	}
	var digest string
	for index := range polys {
		digest += fmt.Sprintf("%x", polys[index])
	}
	return digest
}
