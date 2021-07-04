package lovecrc

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math/big"
	"strconv"
	"time"
)

// N.B.: This project is currently InDev. © 2021 Matthew R Bonnette
/* This file is the reference Go implementation of the LoveCRC hash function as contrived
by its original author. LoveCRC's developer thanks The Go Authors and the developers of
its respective libraries, especially those utilized herein. */

type Digest struct {
	/* Permits the rendering of the digest in more than one way */
	Bytes      []byte /* digest as a slice of raw bytes */
	Str, Str64 string /* digest as hexadecimal and base64 encoded strings */

	/* Allows for verbose output at the functional level (adds milliseconds to total time) */
	ESize int /* size of expanded message */
	/* slices of compressed words and determined polynomials, respectively */
	Block, Polys []uint32
	/* time taken to complete each of the steps: expand, compress, process, form */
	EDelta, CDelta, PDelta, FDelta time.Duration
}

func expand(encoded []byte, ln int) (string, int, time.Duration) {
	t := time.Now()
	encoded = append(encoded, 0x80)
	for len(encoded) < ln/8 || len(encoded)%4 != 0 {
		encoded = []byte(base64.StdEncoding.EncodeToString(encoded))
	}
	return string(encoded), len(encoded), time.Since(t)
}

func compress(expanded string, ln int) ([]uint32, time.Duration) {
	t := time.Now()
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
	ultima := len(block) - 1
	penult := ultima - 1
	for penult != -1 {
		block[penult] = block[penult] ^ block[ultima]
		ultima--
		penult--
	}
	return block[:ln/32], time.Since(t)
}

func process(block []uint32) ([]uint32, time.Duration) {
	t := time.Now()
	for dex := range block {
		word := int64(block[dex])
		for big.NewInt(word).ProbablyPrime(1) != true {
			word--
		}
		block[dex] = uint32(word)
	}
	return block, time.Since(t)
}

func form(msg []byte, polys []uint32) ([]byte, string, string, time.Duration) {
	t := time.Now()
	msg = append(msg, 0x80)
	var bytes []byte
	var str string
	for dex := range polys {
		table := crc32.MakeTable(polys[dex])
		polys[dex] = crc32.Checksum(msg, table)

		segment := make([]byte, 4)
		binary.BigEndian.PutUint32(segment, polys[dex])
		bytes = append(bytes, segment...)
		str += fmt.Sprintf("%x", polys[dex])
	}
	return bytes, str, base64.StdEncoding.EncodeToString(bytes), time.Since(t)
}

func Hash(msg []byte, ln int) Digest {
	/* Checks that the requested digest length meets the function's requirements */
	switch ln {
	case 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024:
		break
	default:
		panic("invalid input: digest length")
	}

	var digest Digest
	var expanded string
	expanded, digest.ESize, digest.EDelta = expand(msg, ln)
	digest.Block, digest.CDelta = compress(expanded, ln)
	digest.Polys, digest.PDelta = process(digest.Block)
	digest.Bytes, digest.Str, digest.Str64, digest.FDelta = form(msg, digest.Polys)
	return digest
}
