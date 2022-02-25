package main

import (
	"encoding/base64"
	"encoding/hex"
	. "fmt"
	"github.com/p7r0x7/rathash/api"
	"github.com/p7r0x7/vainpath"
	. "github.com/spf13/pflag"
	"io"
	"os"
	"runtime"
	"time"
)

// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.
// The code in this file is what allows this hash function to be used as a program: It handles
// command-line flags and arguments, processing files as required by the command-line operator. It
// also enables the printing of a help menu.

var errors, pLength, key = 0, uint(0), []byte(nil)
var pHelp, pBase64, pKeyed, pNoCodes, pQuiet, pRaw, pStrict, pString, pTime bool
var yell, purp, und, zero, star = "\033[33m", "\033[35m", "\033[4m", "\033[0m", ""

func init() {
	for _, arg := range os.Args {
		switch arg {
		case "--quiet":
			pQuiet = true
			fallthrough
		case "--no-codes":
			pNoCodes = true
		}
	}
	if runtime.GOOS == "windows" || pNoCodes {
		yell, purp, und, zero = "", "", "", ""
	}

	BoolVarP(&pHelp, "help", "h", false, purp+"print this help menu"+zero+"\n")

	BoolVarP(&pBase64, "base64", "b", false, purp+"render digests in base64"+zero+" (default hex)")

	/* TODO: Implement checksumming from a list of digests. */

	BoolVarP(&pKeyed, "keyed", "K", false, purp+"use the first 24 bytes of STDIN for keyed hashing"+zero)

	UintVarP(&pLength, "length", "l", 32, purp+"set output digest length in bytes"+zero)

	Bool("no-codes", runtime.GOOS == "windows", purp+"print to console w/o formatting codes or simplified"+zero+"\n"+purp+"filepaths"+zero)

	Bool("quiet", false, purp+"suppress non-breaking errors and print ONLY digests"+zero+"\n(enables --no-codes)")

	BoolVar(&pRaw, "raw", false, purp+"sequentially return the unencoded, non-deliminated bytes"+zero+"\n"+purp+"of each digest"+zero+" (enables --strict)")

	BoolVar(&pStrict, "strict", false, purp+"cause rathash to panic on any error"+zero)

	BoolVarP(&pString, "string", "s", false, purp+"process arguments instead as UTF-8 strings to be hashed"+zero)

	BoolVarP(&pTime, "time", "t", false, purp+"print time taken to read and hash each message"+zero)

	CommandLine.SortFlags = false /* Order flags alphabetically except for help, which is hoisted to the top. */
	Parse()
}

func main() {
	/* Prints the help menu and exits the program if no non-flag arguments are given. In an effort
	to correctly render this menu in most terminal windows, its content should be no wider than 80
	columns. */
	if pHelp || NArg() == 0 {
		Println(yell + "The hopefully—eventually—cryptographic hashing algorithm." + zero + "\n\n" +
			"Usage:\n" +
			"  rathash [-h]\n" +
			"          [-bKt] [-l <uint>] [--quiet|no-codes] [--strict|raw] -|PATH...\n" +
			"          [-bKt] [-l <uint>] [--quiet|no-codes] [--strict|raw] -s STRING...\n\n" +
			"Options:")
		PrintDefaults()
		Println("\nOrder of arguments placed after `rathash` does not matter unless `--` is\n" +
			"specified, signaling the end of parsed flags. Long-form flag equivalents are\n" +
			"above. `-` is treated as a reference to STDIN.")
		os.Exit(0)
	}

	if pRaw {
		pStrict = true
	}

	if pKeyed {
		key = make([]byte, api.KeySize())
		if _, err := io.ReadAtLeast(os.Stdin, key, api.KeySize()); err != nil {
			panic(err)
		}
		star = "(*)"
	}

	for _, path := range Args() {
		digest, start, delta := api.New(pLength), time.Now(), ""

		/* The order of these cases is very deliberate. */
		if pString {
			/* hash.Hash cannot implement (*Writer).WriteString. */
			if _, err := digest.Write([]byte(path)); err != nil {
				warn(err)
				continue
			}
		} else if path == "-" {
			if _, err := io.Copy(digest, os.Stdin); err != nil {
				warn(err)
				continue
			}
		} else {
			if file, err := os.Open(path); err != nil {
				warn(err)
				continue
			} else {
				_, err = io.Copy(digest, file)
				_ = file.Close() /* Error irrelevant */
				if err != nil {
					warn(err)
					continue
				}
			}
		}
		var sum interface{} = digest.Sum(key)

		if pTime {
			delta = " (" + time.Since(start).Truncate(10*time.Microsecond).String() + ")"
		}

		if pRaw {
			if _, err := os.Stdout.Write(sum.([]byte)); err != nil {
				panic(err)
			}
			continue
		}

		if pBase64 {
			sum = base64.StdEncoding.EncodeToString(sum.([]byte))
		} else {
			sum = hex.EncodeToString(sum.([]byte))
		}

		if pString {
			path = "\"" + path + "\""
		} else if !pNoCodes {
			path = und + vainpath.Clean(path) + zero
		}

		if pQuiet {
			Println(sum)
		} else {
			Println(star + yell + sum.(string) + zero + "  " + path + delta)
		}
	}

	if !(pQuiet || pRaw) {
		if errors == 1 {
			Println("1 " + purp + "target is a directory or is otherwise inaccessible." + zero)
		} else if errors > 1 {
			Println(errors, purp+"targets are directories or are otherwise inaccessible."+zero)
		}
	}
	if errors > 0 {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}

func warn(err error) {
	if pStrict {
		panic(err)
	}
	errors++
}
