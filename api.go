package rathash

import (
	"errors"
	"github.com/aead/chacha20/chacha"
	"hash"
	"math/big"
	"reflect"
	"runtime"
	"sync"
	. "unsafe"
)

// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.
// This file contains a Go-specific API implementing the standard hash.Hash interface.

/* TODO: Add API documentation for exported functions. */
/* TODO: Investigate nondeterministic memory allocation. */

type Digest struct {
	dex, read uint64
	offset    [9]byte
	to        chan toPool
	from      chan fromPool
	summing   sync.WaitGroup
	mapping   sync.Mutex

	wCarry     int
	wBuffer    [bytesPerBlock]byte
	list       map[uint64][32]byte
	key, final [bytesPerKey]byte
	stream     *chacha.Cipher
}

type toPool struct {
	dex  uint64
	data [bytesPerBlock]byte
}

type fromPool struct {
	dex uint64
	sum [32]byte
}

const bitsPerReg, bytesPerReg, regsPerBlock = 32 << (^uint(0) >> 63), bitsPerReg / 8, bytesPerBlock / bytesPerReg

var workers, bigZero = runtime.NumCPU(), new(big.Int)
var period, _ = big.NewInt(0).SetString("0x3f_ffff_ffff_ffff_ffff", 0)

func KeySize() int { return bytesPerKey }

func (d *Digest) Size() int { return 0 }

func (d *Digest) BlockSize() int { return bytesPerBlock }

func NewHash(key [32]byte, offset *big.Int) (hash.Hash, error) {
	if offset == nil {
		offset = bigZero
	}

	var bytes [9]byte
	offset.Mod(offset, period).FillBytes(bytes[:])
	return NewDigest(key, bytes)
}

func NewDigest(key [32]byte, offset [9]byte) (*Digest, error) {
	if offset[0] > 64 {
		return nil, errors.New("")
	}
	d := &Digest{list: map[uint64][32]byte{}, key: key, offset: offset}
	d.initWorkers()
	d.initMapper()
	return d, nil
}

func (d *Digest) Write(buf []byte) (count int, err error) {
	count, d.read = len(buf), 0 /* d.final becomes invalid. */

	n := copy(d.wBuffer[d.wCarry:], buf)
	d.wCarry = (d.wCarry + n) % bytesPerBlock
	if d.wCarry != 0 {
		return count, err
	}
	d.to <- toPool{d.dex, d.wBuffer}
	buf = buf[n:]
	d.dex++

	for len(buf) >= bytesPerBlock {
		copy(d.wBuffer[:], buf)
		d.to <- toPool{d.dex, d.wBuffer}
		buf = buf[bytesPerBlock:]
		d.dex++
	}
	d.wCarry = copy(d.wBuffer[:], buf)
	return count, err
}

func (d *Digest) Sum(buf []byte) []byte {
	n := cap(buf) - len(buf)
	if n == 0 {
		return buf
	}
	if d.read == 0 {
		d.finalize() /* TODO: Remove ChaCha from the specification. */
		d.stream, _ = chacha.NewCipher(d.key[:24], d.final[:32], 8)

		// !"#$%&'(  )*+,-./0  12345678  9:;<=>?@  ABCDEFGH  IJKLMNOP  QRSTUVWX  YZ[\]^_`  abcdefgh
		//
		// The above represents the 9-byte structure of Digest.offset with unique symbols for each
		// bit if ! to " is padding, # to b are the upper 64 bits, and c to h are the lowest 6 bits.
		// d.stream's counter must be set to these bits of Digest.offset:
		//
		//     #$%&'()*  +,-./012  3456789:  ;<=>?@AB  CDEFGHIJ  KLMNOPQR  STUVWXYZ  [\]^_`ab
		//
		d.stream.SetCounter(0 |
			uint64(d.offset[0])<<(2+56) |
			uint64(d.offset[1])<<(2+48) |
			uint64(d.offset[2])<<(2+40) |
			uint64(d.offset[3])<<(2+32) |
			uint64(d.offset[4])<<(2+24) |
			uint64(d.offset[5])<<(2+16) |
			uint64(d.offset[6])<<(2+8) |
			uint64(d.offset[7])<<2 |
			uint64(d.offset[8])>>6)

		skip := make([]byte, d.offset[8]&63, 63)
		d.stream.XORKeyStream(skip, skip)
	}
	header := (*reflect.SliceHeader)(Pointer(&buf))
	header.Len = cap(buf)
	rem := buf[len(buf)-n:]

	const bufSize = 512
	var zeroes = make([]byte, bufSize)
	for d.read += uint64(n); n > bufSize; n -= bufSize {
		d.stream.XORKeyStream(rem, zeroes)
		rem = rem[bufSize:]
	}
	d.stream.XORKeyStream(rem, zeroes[:n])
	return buf
}

// TODO: See if RWMutex + an atomic counter is a better method of syncronization...
// as we could reuse the goroutines instead of killing them each time finalize() is called.
func (d *Digest) finalize() {
	close(d.to)
	d.summing.Wait() /* Parallel hashing operations are paused. */
	close(d.from)

	var finalBytes [32]byte
	if d.wCarry > 0 || d.dex == 0 {
		finalBytes = d.primary(d.dex, d.wBuffer, uint(d.wCarry))
	}
	finalWords := (*[bytesPerKey / bytesPerReg]uint)(Pointer(&finalBytes))

	d.mapping.Lock() /* TODO: Replace this cheap, insecure substitute for a proper list hash. */
	for _, sum := range d.list {
		for i, word := range (*[bytesPerKey / bytesPerReg]uint)(Pointer(&sum)) {
			finalWords[i] ^= word
		}
	}
	d.mapping.Unlock()
	d.initWorkers()
	d.initMapper()
	d.final = finalBytes
}

func (d *Digest) Reset() {
	/* TODO: Ensure that secret information is being securely erased. */
	d.dex, d.read, d.wCarry = 0, 0, 0
	carry := (*[regsPerBlock]uint)(Pointer(&d.wBuffer))
	for i := range carry {
		carry[i] = 0
	}
	for k := range d.list {
		delete(d.list, k) /* Optimizes to a memclr(). */
	}
}

func (d *Digest) initWorkers() {
	d.to = make(chan toPool, workers*workers/2)
	d.summing.Add(workers)
	for i := workers; i > 0; i-- {
		go func() {
			for b := range d.to {
				d.from <- fromPool{b.dex, d.primary(b.dex, b.data, bytesPerBlock)}
			}
			d.summing.Done()
		}()
	}
}

func (d *Digest) initMapper() {
	d.from = make(chan fromPool, workers*workers/2)
	go func() {
		d.mapping.Lock()
		for b := range d.from {
			d.list[b.dex] = b.sum
		}
		d.mapping.Unlock()
	}()
}
