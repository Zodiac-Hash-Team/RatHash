package api

import (
	"fmt"
	"github.com/aead/chacha20/chacha"
	"hash"
	"runtime"
	"sync"
)

// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.
// This file contains a Go-specific API implementing the standard hash.Hash interface.

type digest struct {
	ln, dex uint
	ch      chan block
	wg      sync.WaitGroup
	state   sync.Map /* TODO: Test whether or not a map + mutex would be faster. */
	lag     []byte

	buf [bytesPerBlock]byte
}

type block struct {
	dex   uint
	bytes []byte
}

func KeySize() int { return 24 }

func (d *digest) Size() int { return int(d.ln) }

func (d *digest) BlockSize() int { return bytesPerBlock }

func New(ln uint) hash.Hash {
	d := digest{
		ln:    ln,
		state: sync.Map{},
		lag:   make([]byte, 0, bytesPerBlock-1)}

	d.initWorkers()
	return &d
}

func (d *digest) Write(buf []byte) (count int, err error) {
	count = len(buf)
	if len(d.lag) > 0 {
		buf = append(d.lag, buf...)
		d.lag = d.lag[:0]
	}

	rem := len(buf)
	for ; rem >= bytesPerBlock; rem -= bytesPerBlock {
		b := block{d.dex, make([]byte, bytesPerBlock)}
		copy(b.bytes, buf[:bytesPerBlock])
		d.ch <- b

		buf = buf[bytesPerBlock:]
		d.dex++
	}
	if rem > 0 {
		d.lag = d.buf[:rem]
		copy(d.lag, buf)
	}

	return
}

/* TODO: Align Sum() method to its expected usage in hash.Hash. */
func (d *digest) Sum(key []byte) []byte {
	close(d.ch) /* Parallel hashing operations are terminated. */
	if len(key) == 0 {
		/* If key is nil or []byte(nil) or []byte{}, unkeyed hashing is assumed. */
		key = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	} else if len(key) != 24 {
		panic(fmt.Errorf("rathash: key size of %d invalid, must be 24", len(key)))
	}

	if len(d.lag) > 0 {
		b := block{d.dex, make([]byte, len(d.lag), bytesPerBlock)}
		copy(b.bytes, d.lag)
		d.consume(b)
	} else if d.dex == 0 {
		/* This can happen if 0 bytes were written to d. */
		b := block{0, make([]byte, 0, bytesPerBlock)}
		d.consume(b)
	} else {
		d.dex--
	}
	d.wg.Wait()

	/* TODO: Implement Merkle Tree hashing. */
	tmp, _ := d.state.LoadAndDelete(d.dex) /* State alterations are undone. */
	sum := tmp.([32]byte)

	final := make([]byte, d.ln)
	chacha.XORKeyStream(final, final, key, sum[:], 8)
	d.initWorkers() /* Parallel hashing threads are re-established. */
	return final
}

func (d *digest) Reset() {
	/* TODO: Ensure that secret information is being securely erased. */
	close(d.ch)
	d.dex, d.state, d.lag = 0, sync.Map{}, make([]byte, 0, bytesPerBlock-1)
	d.initWorkers()
}

func (d *digest) initWorkers() {
	d.ch = make(chan block)
	d.wg.Add(runtime.NumCPU() * 2)
	for i := runtime.NumCPU() * 2; i > 0; i-- {
		go func() {
			for {
				b, ok := <-d.ch
				if !ok {
					d.wg.Done()
					return
				}
				d.consume(b)
			}
		}()
	}
}
