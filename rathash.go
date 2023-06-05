package rathash

import (
	"github.com/aead/chacha20/chacha"
	"github.com/zeebo/xxh3"
	"math/bits"
	. "unsafe"
)

// N.B.: This project is currently InDev.
// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.
// The following collection of functions backend the reference Go implementation of the RatHash
// cryptographic hashing algorithm as contrived by its original author. RatHash's developer thanks
// The Go Authors and the designers of any third-party software utilized in this project.

const (
	bytesPerWord, bytesPerKey, rounds = 8, 32, bytesPerKey / bytesPerWord
	bytesPerBlock, wordsPerBlock      = 32 << 10, bytesPerBlock / bytesPerWord
	fracPhi, fracPi                   = 0x9e3779b97f4a7c15, 0x243f6a8885a308d3
	rot, rsh, lsh                     = 24, 11, 3

	/* RatHash's compression function employs simply normal Weyl sequences with the constants above
	as described by Hermann Weyl in 1916 and first implemented in pseudorandom number generators by
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
	difference is a different weyl sequence. */

	/* TODO: Do more testing to see if other public constants (various square roots, etc.) yield
	noticibly more entropic sequences for the first wordsPerBlock*rounds values. If so, such
	seeds could make hashes for small messages more secure. */
)

func (d *Digest) primary(dex uint64, data [bytesPerBlock]byte, n uint) [32]byte {

	// Initialization
	sums := [4]uint64{}
	regs, words := (*[regsPerBlock]uint)(Pointer(&data)), (*[wordsPerBlock]uint64)(Pointer(&data))
	unwritten, written := regs[n/bytesPerReg-n/bytesPerBlock:], regs[:n/bytesPerReg-n/bytesPerBlock+1]
	edge, mask := &regs[n/bytesPerReg-n/bytesPerBlock], ^(^uint(0)<<(n%bytesPerReg*8))-n/bytesPerBlock

	// Rounds
	for i, sA := range d.scheduleKey(fracPhi * dex) {
		var prepend = fracPhi * (uint64(i) + rounds*dex) * wordsPerBlock

		for i2 := range written {
			written[i2] ^= uint(0) /* This makes primary() a constant-time operation for all inputs. */
		}
		*edge ^= mask
		for i2 := range unwritten {
			unwritten[i2] ^= ^uint(0) /* This eliminates certain trivial collisions. */
		}

		sB, sC, sCtr := sA, sA, uint64(1)
		for i2 := 0; i2 < 12; i2++ {
			t := sA + sB + sCtr
			sCtr++
			sA = sB ^ sB>>rsh
			sB = sC + sC<<lsh
			sC = t + bits.RotateLeft64(sC, rot)
		}
		for i2 := uint64(0); i2 < wordsPerBlock; i2++ {
			t := sA + sB + sCtr
			sCtr++
			sA = sB ^ sB>>rsh
			sB = sC + sC<<lsh
			sC = t + bits.RotateLeft64(sC, rot)

			next := t%(wordsPerBlock-i2) + i2
			t = words[next] + prepend + fracPhi*(next+1)
			words[next] = words[i2]
			words[i2] = t
		}

		sums[i] = xxh3.Hash(data[:])
	}

	// Return Checksum
	return *(*[32]byte)(Pointer(&sums[0]))
}

func (d *Digest) scheduleKey(nonce uint64) [4]uint64 {
	key := make([]byte, bytesPerKey)
	chacha.XORKeyStream(key, key,
		[]byte{byte(nonce >> 56),
			byte(nonce >> 48),
			byte(nonce >> 40),
			byte(nonce >> 32),
			byte(nonce >> 24),
			byte(nonce >> 16),
			byte(nonce >> 8),
			byte(nonce)},
		d.key[:], 8)
	return *(*[4]uint64)(Pointer(&key[0]))
}
