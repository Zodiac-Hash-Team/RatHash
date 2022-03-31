package api

import (
	"hash/crc32"
	. "math/bits"
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
	/* TODO: Add different weyl sequence constants for the internal tree. */
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

/* TODO: Correct that consume() is not a constant-time operation for inputs smaller than bytesPerBlock. */
func (d *digest) consume(b block) {

	// Initialization
	crc := [2]uint32{crc32.ChecksumIEEE(b.bytes), crc32.Checksum(b.bytes, castagnoli)}
	sums, pHi, pLo, bytes := [8]uint64{}, uint64(0), pcgIV, make([]byte, bytesPerBlock)
	words := (*[wordsPerBlock]uint64)(unsafe.Pointer(&bytes[0]))
	copy(bytes, b.bytes) /* TODO: Find a way to make this unnecessary. */

	// Rounds
	for i := uint(0); i < rounds; i++ {
		weyl := big * uint64(b.dex*rounds+i)
		jA, jB, jC, jD := jsfIV, crc[i&1], crc[i&1], crc[i&1]

		for i2 := uint64(0); i2 < wordsPerBlock; i2++ {
			/* jsf32 generates a pseudorandom permutation of words using a Fisher-Yates shuffle.
			Source available at https://burtleburtle.net/bob/rand/smallprng.html. */
			jE := jA - RotateLeft32(jB, 27)
			jA = jB ^ RotateLeft32(jC, 17)
			jB = jC + jD
			jC = jD + jE
			jD = jE + jA
			next := uint64(jD)%(wordsPerBlock-i2) + i2
			words[i2], words[next] = words[next]+weyl+(next+1)*small, words[i2]

			pLo += words[i2] /* Update lower state. */
			/* pcgmcg128xslrr64 updates sums; the 128-bit multiplication it requires is emulated using
			64-bit values. See https://github.com/imneme/pcg-c/blob/master/include/pcg_variants.h. */
			/* TODO: Obviate 64-bit emulation with ASM. */
			hi, lo := Mul64(pLo, pcgLo)
			hi += pcgHi*pLo + pcgLo*pHi
			pHi, pLo = hi, lo

			/* Decrement the *appropriate* sum. */
			sums[next&7] -= RotateLeft64(pHi^pLo, int(pHi>>58))
			pHi -= sums[next&7] /* Update upper state. */
		}
	}

	// Return Checksum
	folded := [4]uint64{sums[0] ^ sums[4], sums[1] ^ sums[5], sums[2] ^ sums[6], sums[3] ^ sums[7]}
	d.mapping.Lock()
	d.tree[b.dex] = (*[32]byte)(unsafe.Pointer(&folded[0]))[:]
	d.mapping.Unlock()
}

/* TODO: Implement a SumReader() function that enables digest streaming. */
