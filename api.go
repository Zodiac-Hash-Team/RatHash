package rathash

import (
	"errors"
	"github.com/aead/chacha20/chacha"
	"hash"
	"math/big"
	"math/bits"
	"reflect"
	"runtime"
	"sync"
	"unsafe"
)

// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.
// This file contains a Go-specific API implementing the standard hash.Hash interface.

/* TODO: Add API documentation for exported functions. */

type Digest struct {
	dex, read  uint64
	offset     [9]byte
	to, from   chan block
	stream     *chacha.Cipher
	list       map[uint64][32]byte
	summing    sync.WaitGroup
	mapping    sync.Mutex
	final, key [32]byte
	carry      []byte
}

type block struct {
	dex  uint64
	data interface{}
}

var threads = runtime.NumCPU()
var period, _ = big.NewInt(0).SetString("0x3f_ffff_ffff_ffff_ffff", 0)

func KeySize() int { return 32 }

func (d *Digest) Size() int { return 0 }

func (d *Digest) BlockSize() int { return bytesPerBlock }

func NewHash(key [32]byte, offset *big.Int) (hash.Hash, error) {
	if offset == nil {
		offset = big.NewInt(0)
	}

	var bytes [9]byte
	offset.Mod(offset, period).FillBytes(bytes[:])
	return NewDigest(key, bytes)
}

func NewDigest(key [32]byte, offset [9]byte) (*Digest, error) {
	if offset[0] > 64 {
		return nil, errors.New("")
	}
	d := &Digest{
		carry: make([]byte, 0, bytesPerBlock),
		list:  map[uint64][32]byte{},
		key:   key, offset: offset}

	d.initWorkers()
	d.initMapper()
	return d, nil
}

/* TODO: Investigate that 1GiB inputs switch between allocating 4.5 and 6.1 MB. */
func (d *Digest) Write(buf []byte) (int, error) {
	d.read = 0 /* d.final becomes invalid. */
	count := len(buf)
	if len(d.carry) > 0 {
		buf = append(d.carry, buf...)
		d.carry = d.carry[:0]
	}

	for len(buf) >= bytesPerBlock {
		d.to <- block{d.dex, buf[:bytesPerBlock]}
		buf = buf[bytesPerBlock:]
		d.dex++
	}
	if len(buf) > 0 {
		d.carry = append(d.carry, buf...)
	}

	return count, nil
}

func (d *Digest) Sum(buf []byte) []byte {
	n := cap(buf) - len(buf)
	if n == 0 {
		return buf
	}
	if d.read == 0 {
		d.finalize() /* TODO: Remove ChaCha from the specification. */
		d.stream, _ = chacha.NewCipher(d.key[:24], d.final[:32], 8)

		// Below is the 9-byte structure of Digest.offset with unique symbols for each bit:
		// !"#$%&'( )*+,-./0 12345678 9:;<=>?@ ABCDEFGH IJKLMNOP QRSTUVWX YZ[\]^_` abcdefgh
		//
		// ! to " is zero padding; # to b represents the upper 64 bits; c to h lower 6 bits
		//
		// #$%&'()* +,-./012 3456789: ;<=>?@AB CDEFGHIJ KLMNOPQR STUVWXYZ [\]^_`ab
		d.stream.SetCounter(0 |
			uint64(d.offset[0])<<(2+56) | uint64(d.offset[1])<<(2+48) |
			uint64(d.offset[2])<<(2+40) | uint64(d.offset[3])<<(2+32) |
			uint64(d.offset[4])<<(2+24) | uint64(d.offset[5])<<(2+16) |
			uint64(d.offset[6])<<(2+8) | uint64(d.offset[7])<<2 |
			uint64(d.offset[8])>>6)

		skip := make([]byte, d.offset[8]&63, 63)
		d.stream.XORKeyStream(skip, skip)
	}
	header := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
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

	var final [32]byte /* TODO: Replace this cheap, insecure substitute for a proper list hash. */
	if len(d.carry) > 0 || d.dex == 0 {
		final = d.consume(block{d.dex, d.carry}, fracPhi)
	}
	d.mapping.Lock()
	if bits.UintSize == 32 {
		final := (*[8]uint32)(unsafe.Pointer(&final))
		for _, sum := range d.list {
			sum := (*[8]uint32)(unsafe.Pointer(&sum[0]))
			final[0] ^= sum[0]
			final[1] ^= sum[1]
			final[2] ^= sum[2]
			final[3] ^= sum[3]
			final[4] ^= sum[4]
			final[5] ^= sum[5]
			final[6] ^= sum[6]
			final[7] ^= sum[7]
		}
	} else { /* Only one of these blocks gets compiled. */
		final := (*[4]uint64)(unsafe.Pointer(&final))
		for _, sum := range d.list {
			sum := (*[4]uint64)(unsafe.Pointer(&sum[0]))
			final[0] ^= sum[0]
			final[1] ^= sum[1]
			final[2] ^= sum[2]
			final[3] ^= sum[3]
		}
	}
	d.mapping.Unlock()
	d.initWorkers()
	d.initMapper()
	d.final = final
}

func (d *Digest) Reset() {
	/* TODO: Ensure that secret information is being securely erased. */
	d.dex, d.read, d.carry = 0, 0, d.carry[:0]
	if addr := (*[0]byte)(d.carry); bits.UintSize == 32 {
		carry := *(*[bytesPerBlock / 4]uint32)(unsafe.Pointer(addr))
		for i := range carry {
			carry[i] = 0
		}
	} else { /* Only one of these blocks gets compiled. */
		carry := *(*[bytesPerBlock / 8]uint64)(unsafe.Pointer(addr))
		for i := range carry {
			carry[i] = 0
		}
	}
	for k := range d.list {
		delete(d.list, k) /* Optimizes to a memclr(). */
	}
}

func (d *Digest) initWorkers() {
	d.to = make(chan block, threads)
	d.summing.Add(threads)
	for i := threads; i > 0; i-- {
		go func() {
			for b := range d.to {
				d.from <- block{b.dex, d.consume(b, fracPhi)}
			}
			d.summing.Done()
		}()
	}
}

func (d *Digest) initMapper() {
	d.from = make(chan block, threads)
	go func() {
		d.mapping.Lock()
		for b := range d.from {
			d.list[b.dex] = b.data.([32]byte)
		}
		d.mapping.Unlock()
	}()
}
