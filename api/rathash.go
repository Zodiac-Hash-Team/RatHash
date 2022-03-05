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
	pcgHi, pcgLo  = 2549297995355413924, 4865540595714422341
	jsfIV, pcgIV  = uint32(0xf1ea5eed), uint64(0xcafef00dd15ea5e5)
	small, big    = 0x9e3779b97f4a7c15, (small * wordsPerBlock) % (1 << 64)
)

func (d *digest) consume(b block) {
	/* reflect.SliceHeader is necessary because the slice may contain no elements. */
	sums, pHi, pLo, words := [8]uint64{}, uint64(0), pcgIV, (*[wordsPerBlock]uint64)(
		unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&b.bytes)).Data))

	/* jsf32 initialization based on the recommendations of the author.
	Source available at https://burtleburtle.net/bob/rand/smallprng.html. */
	jD := crc32.ChecksumIEEE(b.bytes)
	jA, jB, jC := jsfIV, jD, jD
	for i := 0; i < 19; i++ {
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
			/* pcgmcg128xslrr64 requires 128-bit multiplication; here it is emulated using 64-bit
			values. See https://github.com/imneme/pcg-c/blob/master/include/pcg_variants.h. */
			hi, lo := Mul64(pLo, pcgLo)
			hi += pcgHi*pLo + pcgLo*pHi
			pHi, pLo = hi, lo

			/* Decrement the *appropriate* sum. */
			sums[next&7] -= RotateLeft64(pHi^pLo, int(pHi>>58))
			pHi -= sums[next&7] /* Update upper state. */
		}
	}

	// Return Checksum
	folded, unfolded := [32]byte{}, (*[64]byte)(unsafe.Pointer(&sums[0]))
	for i := 0; i < 32; i++ {
		folded[i] = unfolded[i] ^ unfolded[i+32]
	}
	d.mapping.Lock()
	d.tree[b.dex] = folded[:]
	d.mapping.Unlock()
}

/* TODO: Implement a SumReader() function that is called by Sum() that enables streaming for large digests. */
