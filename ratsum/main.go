package main

import (
	"encoding/base64"
	"encoding/hex"
	. "fmt"
	"github.com/p7r0x7/rathash"
	"github.com/p7r0x7/vainpath"
	. "github.com/spf13/pflag"
	"hash"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime/pprof"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"
)

// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.

const n, bufSize = "\n", 512
const success, failure, invalid = 0, 1, 2

var key, warnings = [32]byte{}, 0

func main() { os.Exit(program()) }

// help prints a usage menu and quietly exits if no non-flag arguments are given. To consistently
// correctly render this menu in most terminal windows, its content should be no wider than 80
// columns.
func help() {
	origin, err := os.Executable()
	if err != nil {
		origin = "ratsum" /* Default binary name */
	} else {
		origin = filepath.Base(origin)
	}
	name := vainpath.Trim(origin, "…", 12)
	spaces := strings.Repeat(" ", utf8.RuneCountInString(name)+3)
	Fprint(os.Stderr, yell, "The hopefully—eventually—cryptographic hashing algorithm.", zero, n+n+
		"Usage:"+n+
		"  ", name, " [-h]"+n,
		spaces, "[-bKt] [-l <uint>] [--quiet|no-codes] [--strict|raw] -|PATH..."+n,
		spaces, "[-bKt] [-l <uint>] [--quiet|no-codes] [--strict|raw] -s STRING..."+n+n+
			"Options:"+n)
	PrintDefaults()
	name = vainpath.Trim(origin, "…", 15)
	Fprint(os.Stderr, n+"Order of arguments placed after `", name, "` does not matter unless `--` is"+
		n+"specified, signaling the end of parsed flags. Long-form flag equivalents are"+n+
		"above. `-` is treated as a reference to ", os.Stdin.Name(), " on this platform."+n)
}

// This program is a command-line interface for rathash: It handles various flags and an unlimited
// number of arguments, processing files as required by the command-line operator.
func program() int {
	if pDebug {
		cf, err := os.Create("cpu.prof")
		_ = pprof.StartCPUProfile(cf)
		defer pprof.StopCPUProfile()

		tf, err := os.Create("goroutine.prof")
		defer pprof.Lookup("goroutine").WriteTo(tf, 0)

		bf, err := os.Create("block.prof")
		defer pprof.Lookup("block").WriteTo(bf, 0)

		af, err := os.Create("allocs.prof")
		defer pprof.Lookup("allocs").WriteTo(af, 0)

		mf, err := os.Create("mutex.prof")
		defer pprof.Lookup("mutex").WriteTo(mf, 0)
		if err != nil {
			panic(err)
		}
	}

	if pHelp || NArg() == 0 {
		help()
		return success
	} else if pLength == 0 {
		panic("Output length should be at least 1 byte.")
	}

	var digest, enc, sum = hash.Hash(nil), interface{}(nil), make([]byte, bufSize)
	if offset, ok := big.NewInt(0).SetString(pOffset, 0); !ok {
		panic("Invalid offset format.")
	} else {
		digest, _ = rathash.NewHash(key, offset)
	}
	if pBase64 {
		enc = base64.NewEncoder(base64.StdEncoding, os.Stdout)
	} else {
		enc = hex.NewEncoder(os.Stdout)
	}

	if pKeyed {
		if _, err := io.ReadAtLeast(os.Stdin, key[:], rathash.KeySize()); err != nil {
			panic(err)
		}
		go os.Stdin.Close() /* STDIN should not be reused. */
		star = "(*)"
	}
	buf := sum[:0]

	for i, target := range Args() {
		if i > 0 {
			digest.Reset()
		}
		start, delta := time.Now(), ""

		if pString {
			/* hash.Hash does not implement (*Writer).WriteString. */
			if _, err := digest.Write(strToBytes(target)); err != nil {
				warn(err)
				continue
			}
		} else if target == "-" || target == os.Stdin.Name() {
			if _, err := io.Copy(digest, os.Stdin); err != nil {
				warn(err)
				continue
			}
			go os.Stdin.Close() /* STDIN should not be reused. */
		} else {
			if file, err := os.Open(target); err != nil {
				warn(err)
				continue
			} else {
				_, err = io.Copy(digest, file)
				go file.Close()
				if err != nil {
					warn(err)
					continue
				}
			}
		}

		if pTime {
			d := time.Since(start)
			if d.Microseconds() > 99 {
				d = d.Truncate(10 * time.Microsecond)
			}
			delta = " (" + d.String() + ")"
		}

		if rem := pLength; pRaw {
			for ; rem > bufSize; rem -= bufSize {
				digest.Sum(buf)
				os.Stdout.Write(sum)
			}
			rem = uint(cap(sum)) - rem
			digest.Sum(sum[rem:rem])
			os.Stdout.Write(sum[rem:])
			continue
		} else {
			if !pQuiet {
				Print(star, yell)
			}
			for ; rem > bufSize; rem -= bufSize {
				digest.Sum(buf)
				enc.(io.Writer).Write(sum)
			}
			rem = uint(cap(sum)) - rem
			digest.Sum(sum[rem:rem])
			enc.(io.Writer).Write(sum[rem:])
			if pBase64 {
				enc.(io.Closer).Close()
			}
		}

		if pQuiet {
			os.Stdout.WriteString(n)
		} else if pString {
			Print(zero, `  "`, target, `"`, zero, delta, n)
		} else if pNoCodes {
			Print(`  `, filepath.Clean(target), delta, n)
		} else {
			Print(zero, `  `, und, vainpath.Simplify(target), zero, delta, n)
		}
	}

	if !(pQuiet || pRaw) {
		if warnings == 1 {
			Fprint(os.Stderr, "1 ", purp, "target is a directory or is otherwise inaccessible.", zero, n)
		} else if warnings > 1 {
			Fprint(os.Stderr, warnings, " ", purp, "targets are directories or are otherwise inaccessible.", zero, n)
		}
	}
	if warnings > 0 {
		return failure
	}
	return success
}

// strToBytes converts any string into a byte slices without allocating memory; as discussed in
// https://stackoverflow.com/a/69231355, this practice is safe so long as the underlying memory is
// not modified during its lifetime.
func strToBytes(s string) []byte {
	const MaxInt32 = 1<<31 - 1
	return (*[MaxInt32]byte)(unsafe.Pointer((*reflect.StringHeader)(
		unsafe.Pointer(&s)).Data))[: len(s)&MaxInt32 : len(s)&MaxInt32]
}

func warn(err ...interface{}) {
	if pStrict {
		panic(err)
	}
	warnings++
}
