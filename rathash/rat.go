package rathash

import (
	"encoding/base64"
	"hash/crc64"
	"math/bits"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

// N.B.: This project is currently InDev. Copyright © 2021 Matthew R Bonnette.
/* This file is the reference Go implementation of the RatHash function as contrived by its original
author. RatHash's developer thanks The Go Authors and the developers of its respective libraries,
especially those utilized herein. */

type Digest struct {
	// Permits the rendering of the digest in more than one way
	Bytes      []byte /* digest as a slice of raw bytes */
	Str, Str64 string /* digest as hexadecimal and base64 encoded strings */

	// Allows for verbose output at the functional level
	BSize int /* internal block size  */
	/* slices of compressed words and determined polynomials, respectively */
	Polys []uint64
	/* time taken to complete each of the steps: expand, divide, process, form */
	EDelta, DDelta, PDelta, FDelta time.Duration
}

func Hash(msg *[]byte, ln int) Digest {
	/* Checks that the requested digest length meets the function's requirements */
	switch {
	case ln >= 256 && ln%64 == 0:
		break
	default:
		panic("invalid input: digest length")
	}
	var (
		expanded []byte
		blocks   [][]byte
		group    sync.WaitGroup
		digest   Digest
	)

	// PRELIMINARY EXPANSION
	t := time.Now()
	expanded = *msg
	if len(expanded) < ln/4 {
		expanded = append(expanded, 0x40)
		for len(expanded) < ln/4 {
			expanded = []byte(base64.StdEncoding.EncodeToString(expanded))
		}
	}
	digest.EDelta = time.Since(t)

	// MESSAGE DIVISION
	t = time.Now()
	for len(expanded)%(ln/64) != 0 {
		expanded = append(expanded, 0x40)
	}
	bSize := len(expanded) / (ln / 64)
	for len(expanded) != 0 {
		blocks = append(blocks, expanded[:bSize])
		expanded = expanded[bSize:]
	}
	digest.DDelta = time.Since(t)

	// PARALLELIZED PROCESSING
	t = time.Now()
	digest.Polys = make([]uint64, ln/64)
	for i := range blocks {
		group.Add(1)
		go func(i int) {
			/* Supplemental expansion */
			for len(blocks[i])%8 != 0 {
				blocks[i] = append(blocks[i], 0x40)
			}

			/* Converts each block of bytes into a block of uint64's */
			block := make([]uint64, bSize/8)
			for i2 := range block {
				/* Little-endian */
				block[i2] = *(*uint64)(unsafe.Pointer(&blocks[i][i2*8]))
			}

			/* In descending order and starting with the penultimate word, assign each word with the
			result of itself XORred by its predecessor bit-rotated by 1 to the left. */
			ultima := len(block) - 1
			penult := ultima - 1
			for penult != -1 {
				block[penult] ^= bits.RotateLeft64(block[ultima], 1)
				ultima--
				penult--
			}
			block[len(block)-1] ^= bits.RotateLeft64(block[0], 1)
			/* Mark the 64-bit word at index 0 as the polynomial for this block. */
			digest.Polys[i] = block[0]

			/* Assign the processed words as the []byte content of the block they came from. */
			for i2 := range block {
				blocks[i][0+i2*8] = byte(block[i2])
				blocks[i][1+i2*8] = byte(block[i2] >> 8)
				blocks[i][2+i2*8] = byte(block[i2] >> 16)
				blocks[i][3+i2*8] = byte(block[i2] >> 24)
				blocks[i][4+i2*8] = byte(block[i2] >> 32)
				blocks[i][5+i2*8] = byte(block[i2] >> 40)
				blocks[i][6+i2*8] = byte(block[i2] >> 48)
				blocks[i][7+i2*8] = byte(block[i2] >> 56)
			}
			group.Done()
		}(i)
	}
	group.Wait()
	digest.PDelta = time.Since(t)

	// DIGEST FORMATION
	t = time.Now()
	/* Making each block depend on the contents of each other */
	ultima := ln/64 - 1
	penult := ultima - 1
	for penult != -1 {
		digest.Polys[penult] ^= bits.RotateLeft64(digest.Polys[ultima], 1)
		ultima--
		penult--
	}
	digest.Polys[ln/64-1] ^= bits.RotateLeft64(digest.Polys[0], 1)

	sums := make([]uint64, ln/64)
	digest.Bytes = make([]byte, ln/8)
	for i := range digest.Polys {
		group.Add(1)
		go func(i int) {
			/* Perfoming final checksum of each block */
			table := crc64.MakeTable(digest.Polys[i])
			sums[i] = crc64.Checksum(blocks[i], table)
			/* Little-endian */
			digest.Bytes[0+i*8] = byte(sums[i])
			digest.Bytes[1+i*8] = byte(sums[i] >> 8)
			digest.Bytes[2+i*8] = byte(sums[i] >> 16)
			digest.Bytes[3+i*8] = byte(sums[i] >> 24)
			digest.Bytes[4+i*8] = byte(sums[i] >> 32)
			digest.Bytes[5+i*8] = byte(sums[i] >> 40)
			digest.Bytes[6+i*8] = byte(sums[i] >> 48)
			digest.Bytes[7+i*8] = byte(sums[i] >> 56)
			group.Done()
		}(i)
	}
	group.Wait()
	for i := range digest.Polys {
		digest.Str += strconv.FormatUint(sums[i], 16)
	}
	digest.Str64 = base64.StdEncoding.EncodeToString(digest.Bytes)
	digest.FDelta = time.Since(t)

	//fmt.Println(digest)
	return digest
}
