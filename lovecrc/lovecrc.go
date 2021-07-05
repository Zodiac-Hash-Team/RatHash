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

var length int
var digest = Digest{
	Block: make([]uint32, length/32),
	Polys: make([]uint32, length/32),
}

func expand(enc []byte) (*[]uint32, int, time.Duration) {
	t := time.Now()
	for len(enc) < length/8 || len(enc)%4 != 0 {
		enc = []byte(base64.StdEncoding.EncodeToString(enc))
	}
	exp := string(enc)

	var split []string
	for len(exp) != 0 {
		split = append(split, exp[:4])
		exp = exp[4:]
	}
	blk := make([]uint32, len(split))
	for dex := range split {
		word, _ := strconv.ParseUint(fmt.Sprintf("%x", split[dex]), 16, 32)
		blk[dex] = uint32(word)
	}
	return &blk, len(enc), time.Since(t)
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

func process(blk *[]uint32) time.Duration {
	t := time.Now()
	for dex := range *blk {
		word := int64((*blk)[dex])
		for big.NewInt(word).ProbablyPrime(1) != true {
			word--
		}
		(*blk)[dex] = uint32(word)
	}
	return time.Since(t)
}

func form(msg *[]byte, polys *[]uint32) ([]byte, string, string, time.Duration) {
	t := time.Now()
	var bytes []byte
	var str string
	for dex := range *polys {
		table := crc32.MakeTable((*polys)[dex])
		(*polys)[dex] = crc32.Checksum(*msg, table)

		segment := make([]byte, 4)
		binary.BigEndian.PutUint32(segment, (*polys)[dex])
		bytes = append(bytes, segment...)
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

	var block *[]uint32
	*msg = append(*msg, 0x80)
	block, digest.ESize, digest.EDelta = expand(*msg)
	digest.CDelta = compress(block)
	_ = copy(digest.Block, *block)
	digest.PDelta = process(block)
	_ = copy(digest.Polys, *block)
	digest.Bytes, digest.Str, digest.Str64, digest.FDelta = form(msg, block)
	*msg = (*msg)[:len(*msg)-1]
	return digest
}
