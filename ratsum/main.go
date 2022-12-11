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
	"log"
	"math/big"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"time"
	"unicode/utf8"
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
	Print(yell, "The hopefully—eventually—cryptographic hashing algorithm.", zero, n+n+
		"Usage:"+n+
		"  ", name, " [-h]"+n,
		spaces, "[-bKt] [-l <uint>] [--quiet|no-codes] [--strict|raw] -|PATH..."+n,
		spaces, "[-bKt] [-l <uint>] [--quiet|no-codes] [--strict|raw] -s STRING..."+n+n+
			"Options:"+n)
	PrintDefaults()
	name = vainpath.Trim(origin, "…", 15)
	Print(n+"Order of arguments placed after `", name, "` does not matter unless `--` is"+n+
		"specified, signaling the end of parsed flags. Long-form flag equivalents are"+n+
		"above. `-` is treated as a reference to "+os.Stdin.Name()+" on this platform."+n)
}

// This program is a command-line interface for rathash: It handles various flags and an unlimited
// number of arguments, processing files as required by the command-line operator. It also enables
// the printing of a usage menu.
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
	} else {
		defer func() {
			if err := recover(); err != nil {
				quit(err)
			}
		}()
	}

	if pHelp || NArg() == 0 {
		help()
		return success
	}
	if pLength == 0 {
		Fprint(os.Stderr, purp, "Output length should be at least 1 byte.", zero, n)
		return 2
	}

	var digest, enc, sum = hash.Hash(nil), interface{}(nil), make([]byte, bufSize)
	if offset, ok := big.NewInt(0).SetString(pOffset, 0); !ok {
		Fprint(os.Stderr, purp, "Invalid offset format.", zero, n)
		return 2
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
			quit(err)
		}
		_ = os.Stdin.Close()
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
			if _, err := digest.Write([]byte(target)); err != nil {
				warn(err)
				continue
			}
		} else if target == "-" || target == os.Stdin.Name() {
			if _, err := io.Copy(digest, os.Stdin); err != nil {
				warn(err)
				continue
			}
			_ = os.Stdin.Close()
		} else {
			if file, err := os.Open(target); err != nil {
				warn(err)
				continue
			} else {
				_, err = io.Copy(digest, file)
				if _ = file.Close(); err != nil {
					warn(err)
					continue
				}
			}
		}
		if d := time.Since(start); pTime {
			if d.Microseconds() > 99 {
				d = d.Truncate(10 * time.Microsecond)
			}
			delta = " (" + d.String() + ")"
		}
		if pRaw {
			rem := pLength
			for ; rem > bufSize; rem -= bufSize {
				digest.Sum(buf)
				os.Stdout.Write(sum)
			}
			rem = uint(cap(sum)) - rem
			digest.Sum(sum[rem:rem])
			os.Stdout.Write(sum[rem:])
			continue
		}

		if !pQuiet {
			Print(star, yell)
		}
		rem := pLength
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
		if !pQuiet {
			if pString {
				Print(zero, `  "`, target, `"`, delta)
			} else if pNoCodes {
				Print(`  `, filepath.Clean(target), delta)
			} else {
				Print(zero, `  `, und, vainpath.Simplify(target), zero, delta)
			}
		}
		os.Stdout.WriteString(n)
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

func warn(err ...interface{}) {
	if pStrict {
		quit(err)
	}
	warnings++
}

func quit(err ...interface{}) {
	if pDebug {
		panic(err)
	}
	log.Fatal(purp, err, zero)
}
