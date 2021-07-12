package rathash

import (
	"encoding/base64"
	"hash/crc64"
	"math/big"
	"strconv"
	"time"
	"unsafe"
)

// N.B.: This project is currently Deprecated. Copyright © 2021 Matthew R Bonnette.
/* This file is the reference Go implementation of the RatHash function as contrived by its original
author. RatHash's developer thanks The Go Authors and the developers of its respective libraries,
especially those utilized herein. */

type Digest struct {
	// Permits the rendering of the digest in more than one way
	Bytes      []byte /* digest as a slice of raw bytes */
	Str, Str64 string /* digest as hexadecimal and base64 encoded strings */

	// Allows for verbose output at the functional level
	ESize int /* size of expanded message */
	/* slices of compressed words and determined polynomials, respectively */
	Block []uint32
	Polys []uint64
	/* time taken to complete each of the steps: expand, compress, process, form */
	EDelta, CDelta, PDelta, FDelta time.Duration
}

func Hash(msg *[]byte, ln int) Digest {
	var (
		length   int
		message  *[]byte
		expanded []byte
		block    []uint32
		polys    []uint64
		digest   Digest
	)
	length = ln
	/* Checks that the requested digest length meets the function's requirements */
	switch length {
	case 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024:
		break
	default:
		panic("invalid input: digest length")
	}
	message = msg

	// EXPANSION FUNCTION
	t := time.Now()
	*message = append(*message, 0x80)
	expanded = *message
	for len(expanded) < length/8 || len(expanded)%4 != 0 {
		expanded = []byte(base64.StdEncoding.EncodeToString(expanded))
	}
	digest.ESize = len(expanded)
	digest.EDelta = time.Since(t)

	// COMPRESSION FUNCTION
	t = time.Now()
	block = make([]uint32, len(expanded)/4)
	for i := range block {
		/* Little-endian */
		block[i] = *(*uint32)(unsafe.Pointer(&expanded[i*4]))
	}
	ultima := len(block) - 1
	penult := ultima - 1
	for penult != -1 {
		block[penult] ^= block[ultima]
		ultima--
		penult--
	}
	block = block[:length/32]
	digest.Block = append(digest.Block, block...)
	digest.CDelta = time.Since(t)

	// PRIMALITY-BASED PROCESSING
	t = time.Now()
	for i := range block {
		word := int64(block[i])
		for big.NewInt(word).ProbablyPrime(1) != true {
			word--
		}
		block[i] = uint32(word)
	}
	polys = make([]uint64, length/64)
	for i := range polys {
		/* Little-endian */
		polys[i] = *(*uint64)(unsafe.Pointer(&block[i*2]))
	}
	digest.Polys = append(digest.Polys, polys...)
	digest.PDelta = time.Since(t)

	// DIGEST FORMATION
	t = time.Now()
	var bytes []byte
	var str string
	for i := range polys {
		go func() {
			table := crc64.MakeTable(polys[i])
			polys[i] = crc64.Checksum(*message, table)
		}()
		tmp := [8]byte{
			byte(polys[i] >> 56), byte(polys[i] >> 48), byte(polys[i] >> 40), byte(polys[i] >> 32),
			byte(polys[i] >> 24), byte(polys[i] >> 16), byte(polys[i] >> 8), byte(polys[i]),
		}
		bytes = append(bytes, tmp[:]...)
		str += strconv.FormatUint(polys[i], 16)
	}
	digest.Bytes = bytes
	digest.Str = str
	digest.Str64 = base64.StdEncoding.EncodeToString(bytes)
	*message = (*message)[:len(*message)-1]
	digest.FDelta = time.Since(t)

	return digest
}
