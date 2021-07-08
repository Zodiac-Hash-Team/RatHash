package lovecrc

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc64"
	"math/big"
	"time"
	"unsafe"
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

var (
	length   int
	message  *[]byte
	expanded []byte
	block    []uint32
	polys    []uint64
	digest   Digest
)

func expand() {
	t := time.Now()
	*message = append(*message, 0x80)
	expanded = *message
	for len(expanded) < length/8 || len(expanded)%4 != 0 {
		expanded = []byte(base64.StdEncoding.EncodeToString(expanded))
	}
	digest.ESize = len(expanded)
	digest.EDelta = time.Since(t)
}

func compress() {
	t := time.Now()
	block = make([]uint32, len(expanded)/4)
	for dex := range block {
		/* Little-endian */
		block[dex] = *(*uint32)(unsafe.Pointer(&expanded[dex*4]))
	}
	ultima := len(block) - 1
	penult := ultima - 1
	for penult != -1 {
		block[penult] = block[penult] ^ block[ultima]
		ultima--
		penult--
	}
	block = block[:length/32]
	digest.Block = append(digest.Block, block...)
	digest.CDelta = time.Since(t)
}

func process() {
	t := time.Now()
	for dex := range block {
		word := int64(block[dex])
		for big.NewInt(word).ProbablyPrime(1) != true {
			word--
		}
		block[dex] = uint32(word)
	}
	polys = make([]uint64, length/64)
	for dex := range polys {
		/* Little-endian */
		polys[dex] = *(*uint64)(unsafe.Pointer(&block[dex*2]))
	}
	digest.Polys = append(digest.Polys, polys...)
	digest.PDelta = time.Since(t)
}

func form() {
	t := time.Now()
	var bytes []byte
	var str string
	for dex := range polys {
		go func() {
			table := crc64.MakeTable(polys[dex])
			polys[dex] = crc64.Checksum(*message, table)
		}()
		tmp := make([]byte, 8)
		binary.LittleEndian.PutUint64(tmp, polys[dex])
		bytes = append(bytes, tmp...)
		str += fmt.Sprintf("%x", polys[dex])
	}
	digest.Bytes = bytes
	digest.Str = str
	digest.Str64 = base64.StdEncoding.EncodeToString(bytes)
	*message = (*message)[:len(*message)-1]
	digest.FDelta = time.Since(t)
}

func Hash(msg *[]byte, ln int) Digest {
	length = ln
	/* Checks that the requested digest length meets the function's requirements */
	switch length {
	case 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024:
		break
	default:
		panic("invalid input: digest length")
	}
	message = msg
	expand()
	compress()
	process()
	form()
	return digest
}
