package api

import (
	"hash/crc32"
	. "math/bits"
	"reflect"
	"unsafe"
)

// N.B.: This project is currently InDev.
// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.
// The following collection of functions backend the reference Go implementation of the RatHash
// cryptographic hashing algorithm as contrived by its original author. RatHash's developer thanks
// The Go Authors and the designers of any third-party software utilized in this project.

const (
	rounds        = 4
	bytesPerBlock = 32 * 1024
	wordsPerBlock = bytesPerBlock / 8
	jsfConst      = uint32(0xf1ea5eed)
	pcgHi, pcgLo  = 2549297995355413924, 4865540595714422341
	small, big    = 0x9e3779b97f4a7c15, (small * wordsPerBlock) % (1 << 64)
)

func (d *digest) consume(b block) {
	/* This creates a uint64 slice pointing to the bytes of the block. */
	/* TODO: Potentially reduce this/remove the dependency on Go 1.17+ altogether. */
	words := unsafe.Slice((*uint64)(unsafe.Pointer(
		(*reflect.SliceHeader)(unsafe.Pointer(&b.bytes)).Data)), wordsPerBlock)
	sums, pHi, pLo := [8]uint64{}, uint64(0), uint64(0)

	/* jsf32 initialization based on the recommendations of the author.
	Source available at https://burtleburtle.net/bob/rand/smallprng.html. */
	jD := crc32.Checksum(b.bytes, crc32.MakeTable(crc32.IEEE))
	jA, jB, jC := jsfConst, jD, jD
	for i := 19; i > 0; i-- {
		jE := jA - RotateLeft32(jB, 27)
		jA = jB ^ RotateLeft32(jC, 17)
		jB = jC + jD
		jC = jD + jE
		jD = jE + jA
	}

	// Rounds
	for i := uint(0); i < rounds; i++ {
		weyl := big * uint64(b.dex*(rounds+i))

		for i2 := uint64(0); i2 < wordsPerBlock; i2++ {
			/* Find next word to process. */
			jE := jA - RotateLeft32(jB, 27)
			jA = jB ^ RotateLeft32(jC, 17)
			jB = jC + jD
			jC = jD + jE
			jD = jE + jA
			/* Note: jD cannot be safely cast to int on 32-bit systems. */
			next := uint64(jD)%(wordsPerBlock-i2) + i2

			/* Increment by counter and swap indicies. */
			t := words[i2]
			words[i2] = small*(next+1) + weyl + words[next]
			words[next] = t

			pLo += words[i2] /* Update lower state. */
			/* pcgmcg128xslrr64 requires 128-bit multiplication; here it is emulated using
			64-bit values. */
			hi, lo := Mul64(pLo, pcgLo)
			hi += pcgHi*pLo + pcgLo*pHi
			pHi, pLo = hi, lo

			/* Decrement the *appropriate* sum. */
			sums[next&7] -= RotateLeft64(pHi^pLo, int(pHi>>58))
			pHi -= sums[next&7] /* Update upper state. */
		}
	}

	// Return Checksum
	folded, unfolded := [32]byte{}, unsafe.Slice((*byte)(unsafe.Pointer(&sums[0])), 64)
	for i := range folded {
		folded[i] = unfolded[i] ^ unfolded[i+32]
	}
	d.state.Store(b.dex, folded)
}

/* TODO: Implement a SumReader() function that is called by Sum() that enables streaming for large digests. */
