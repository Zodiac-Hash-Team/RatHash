package lovecrc

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc64"
	"math/big"
	"time"
)

// N.B.: This project is currently InDev. © 2021 Matthew R Bonnette
/* This file is the reference Go implementation of the LoveCRC hash function as contrived
by its original author. LoveCRC's developer thanks The Go Authors and the developers of
its respective libraries, especially those utilized herein. */

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

var length int

func expand(enc []byte) (*[]uint32, int, time.Duration) {
	t := time.Now()
	for len(enc) < length/8 || len(enc)%4 != 0 {
		enc = []byte(base64.StdEncoding.EncodeToString(enc))
	}
	split := make([]uint32, len(enc)/4)
	for dex := range split {
		split[dex] = uint32(enc[0+dex*4])<<24 | uint32(enc[1+dex*4])<<16 |
			uint32(enc[2+dex*4])<<8 | uint32(enc[3+dex*4])
	}
	return &split, len(enc), time.Since(t)
}

func compress(blk *[]uint32) time.Duration {
	t := time.Now()
	ultima := len(*blk) - 1
	penult := ultima - 1
	for penult != -1 {
		(*blk)[penult] = (*blk)[penult] ^ (*blk)[ultima]
		ultima--
		penult--
	}
	*blk = (*blk)[:length/32]
	return time.Since(t)
}

func process(blk *[]uint32) (*[]uint64, time.Duration) {
	t := time.Now()
	for dex := range *blk {
		word := int64((*blk)[dex])
		for big.NewInt(word).ProbablyPrime(1) != true {
			word--
		}
		(*blk)[dex] = uint32(word)
	}
	polys := make([]uint64, length/64)
	for dex := range polys {
		polys[dex] = uint64((*blk)[0+dex*2])<<32 | uint64((*blk)[1+dex*2])
	}
	return &polys, time.Since(t)
}

func form(msg *[]byte, polys *[]uint64) ([]byte, string, string, time.Duration) {
	t := time.Now()
	var bytes []byte
	var str string
	for dex := range *polys {
		table := crc64.MakeTable((*polys)[dex])
		(*polys)[dex] = crc64.Checksum(*msg, table)

		split := make([]byte, 8)
		binary.BigEndian.PutUint64(split, (*polys)[dex])
		bytes = append(bytes, split...)
		str += fmt.Sprintf("%x", (*polys)[dex])
	}
	return bytes, str, base64.StdEncoding.EncodeToString(bytes), time.Since(t)
}

func Hash(msg *[]byte, ln *int) Digest {
	length = *ln
	/* Checks that the requested digest length meets the function's requirements */
	switch length {
	case 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024:
		break
	default:
		panic("invalid input: digest length")
	}

	/* Declare helper variables and prep the value behind pointer msg by appending a byte. */
	var (
		digest Digest
		blk    *[]uint32
		polys  *[]uint64
	)
	*msg = append(*msg, 0x80)
	/* Call the expansion function on the value behind msg. */
	blk, digest.ESize, digest.EDelta = expand(*msg)
	/* Call the compression function on pointer blk and copy the resulting values behind
	it to digest.Block. */
	digest.CDelta = compress(blk)
	digest.Block = append(digest.Block, *blk...)
	/* Process blk and copy the resulting values behind polys to digest.Polys. */
	polys, digest.PDelta = process(blk)
	digest.Polys = append(digest.Polys, *polys...)
	/* Form the digest as raw bytes, a hexadecimal string, and a base64 string. */
	digest.Bytes, digest.Str, digest.Str64, digest.FDelta = form(msg, polys)
	/* Remove the added byte from msg. */
	*msg = (*msg)[:len(*msg)-1]
	return digest
}
