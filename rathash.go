package rathash

import (
	"math/bits"
	. "unsafe"
)

// N.B.: This project is currently InDev.
// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.
// The following collection of functions backend the reference Go implementation of the RatHash
// cryptographic hashing algorithm as contrived by its original author. RatHash's developer thanks
// The Go Authors and the designers of any third-party software utilized in this project.

const (
	rounds          = 5
	bytesPerBlock   = 32 << 10
	wordsPerBlock   = bytesPerBlock / 8
	pcgHi, pcgLo    = 2549297995355413924, 4865540595714422341
	fracPhi, fracPi = 0x9e3779b97f4a7c15, 0x243f6a8885a308d3
	/* RatHash's compression function employs simply normal Weyl sequences with the constants above
	as described by Hermann Weyl in 1916 and first implemented in pseudo-random number generators by
	George Marsaglia in his 2003 publication "Xorshift RNGs" https://doi.org/10.18637/jss.v008.i14.
	Index 0—which is always 0 for any given seed—is skipped here, but successive values are added to
	words of each block as they are processed each round. This dramatically increases the complexity
	of the hash calculation and the unpredictability of its output for every possible input and does
	so uniquely for each round of each block compressed. This property makes RatHash immune to
	length extension attacks.

	Due to the binary representation of data stored in and manipulated by computers, the only
	stipulation for a given Weyl sequnce seed is that it is odd, as all odd numbers are relatively
	prime to any modulo that is a factor of 2, such as 2^64. Beyond that stipulation, however, seeds
	with Hamming weights closer to 50% tend to much more quickly yield digit uniformity as the
	sequence progresses. Therefore, the known, random-looking first 16 fractional hexadecimal digits
	of the golden ratio and pi were chosen (those two specifically because those values happen to
	end with odd numbers).

	Why two values? As it happens, this is a hash list-based algorithm, and without some difference
	between the initial hash calculation and the internal product hashing, an attacker can trivially
	perform a second-preimage attack based off the final hash of a given message. Here, that
	difference is different weyl sequence.

	TODO: Do more testing to see if other public constants (various square roots, etc.) yield
	noticibly more entropic sequences for the first wordsPerBlock*rounds values. If so, such
	seeds could make hashes for small messages more secure. */
)

func (d *Digest) consume(b block, seed uint64) [32]byte {

	// Initialization
	written, sums, key := make([]byte, bytesPerBlock), [8]uint64{}, d.scheduleKey(b.dex)
	n, words := copy(written, b.data.([]byte)), (*[wordsPerBlock]uint64)(Pointer(&written[0]))[:]
	unwritten := written[n:]
	written = written[:n] /* Bounds check eliminated. */

	// Rounds
	for i := uint64(0); i < rounds; i++ {
		/* Only the following reset each round: */
		prepend := (b.dex*rounds + i) * wordsPerBlock * seed
		var subkey, pHi, pLo, val uint64
		if i < 4 {
			subkey = key[i]
		}
		for i2 := range written {
			/* This makes consume() a constant-time operation for all inputs. */
			written[i2] ^= 0x00 /* This *must not* be optimized out. */
		}
		for i2 := range unwritten {
			/* This eliminates certain trivial collisions. */
			unwritten[i2] ^= 0xff
		}

		for i2 := uint64(0); i2 < wordsPerBlock; i2++ {
			next := val%(wordsPerBlock-i2) + i2
			t := words[next] + prepend + seed*(next+1)
			words[next] = words[i2]
			words[i2] = t - subkey /* Key element for the next round. */

			pLo += t /* Update lower state. */
			/* pcgmcg128xslrr64 updates sums; the 128-bit multiplication it requires is emulated using
			64-bit values. See https://github.com/imneme/pcg-c/blob/master/include/pcg_variants.h. */
			/* TODO: Obviate 64-bit emulation with 128-bit SIMD ASM. */
			hi, lo := bits.Mul64(pLo, pcgLo)
			hi += pcgHi*pLo + pcgLo*pHi
			pHi, pLo = hi, lo
			val = bits.RotateLeft64(pHi^pLo, int(pHi>>58))

			sums[next&7] -= val /* Decrement the *appropriate* sum. */
		}
	}

	// Return Checksum
	folded := [4]uint64{sums[0] ^ sums[4], sums[1] ^ sums[5], sums[2] ^ sums[6], sums[3] ^ sums[7]}
	return *(*[32]byte)(Pointer(&folded[0]))
}

func (d *Digest) scheduleKey(dex uint64) [4]uint64 {
	dex++
	key := [4]uint64{
		dex * (dex + *(*uint64)(Pointer(&d.key[0]))),
		dex * (dex + *(*uint64)(Pointer(&d.key[8]))),
		dex * (dex + *(*uint64)(Pointer(&d.key[16]))),
		dex * (dex + *(*uint64)(Pointer(&d.key[24])))}

	var jA, jB, jC, jD uint64
	for _, v := range key {
		jA = 0xf1ea5eed
		jB -= v
		jC -= v
		jD -= v
		for i2 := 10; i2 > 0; i2-- {
			jE := jA - bits.RotateLeft64(jB, 7)
			jA = jB ^ bits.RotateLeft64(jC, 13)
			jB = jC + bits.RotateLeft64(jD, 37)
			jC = jD + jE
			jD = jE + jA
		}
	}
	return [4]uint64{jA, jB, jC, jD}
}
