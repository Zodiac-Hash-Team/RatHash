package main

import (
	"encoding/base64"
	. "fmt"
	"github.com/p7r0x7/rathash/api"
	"github.com/p7r0x7/vainpath"
	. "github.com/spf13/pflag"
	"io/ioutil"
	"os"
	"runtime"
	"time"
)

// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.
// The code in this file is what allows this hash function to be used as a program: It handles
// command-line flags and arguments, processing files as required by the command-line operator. It
// also enables the printing of a help menu.

var (
	err      error
	exit     int
	readErrs int
	noFormat bool
	quiet    bool
)

func main() {
	for i := range os.Args {
		switch os.Args[i] {
		case "--no-formatting":
			noFormat = true
		case "--quiet":
			quiet = true
		}
	}
	yell, purp, und, zero := "\033[33m", "\033[35m", "\033[4m", "\033[0m" /* As in zero formatting */
	if runtime.GOOS == "windows" || noFormat || quiet {
		yell, purp, und, zero = "", "", "", ""
	}

	pHelp := BoolP("help", "h", false, purp+"prints this help menu"+zero+"\n")

	pBase64 := BoolP("base64", "b", false, purp+"renders digest as base64 string"+zero+" (default hex string)")

	pLength := IntP("length", "l", 256, purp+"sets output digest length in bits"+zero)

	Bool("no-formatting", false, purp+"prints to console without formatting codes"+zero+"\n(always true on windows)")

	Bool("quiet", false, purp+"prints ONLY digests or breaking errors"+zero+"\n(disables formatting)")

	pString := BoolP("string", "s", false, purp+"process arguments instead as UTF-8 strings to be hashed"+zero)

	pTime := BoolP("time", "t", false, purp+"prints time taken to process each message"+zero)
	/* Ordered alphabetically except for help, which is hoisted to the top. */
	CommandLine.SortFlags = false
	Parse()

	/* Prints the help menu and exits the program if no other arguments are given. */
	if *pHelp || NArg() == 0 {
		Println(yell + "The hopefully—eventually—cryptographic hashing algorithm." + zero + "\n\n" +
			"Usage:\n" +
			"  rathash [-h] [--quiet|no-formatting]\n" +
			"          [-b] [--quiet|no-formatting] [-l <int>|l=<int>] -|FILE...\n" +
			"          [-b] [-t] [--no-formatting] [-l <int>|l=<int>] -|FILE...\n" +
			"          [-b] [--quiet|no-formatting] [-l <int>|l=<int>] -s STRING...\n" +
			"          [-b] [-t] [--no-formatting] [-l <int>|l=<int>] -s STRING...\n\n" +
			"Options:")
		PrintDefaults()
		Println("\nOrder of arguments placed after `rathash` does not matter unless `--` is\n" +
			"specified, signaling the end of parsed flag groups. Long-form flag equivalents\n" +
			"are above. `-` is treated as a reference to STDIN.")
		os.Exit(0)
	}

	/* Checks that the requested digest length meets the function's requirements */
	if *pLength < 256 || *pLength%64 != 0 {
		Println(purp + "Digest length in bits must be at least 256 and evenly divisible by 64." + zero)
		os.Exit(1)
	}

	for i := range Args() {
		var message []byte
		path := Arg(i)
		switch {
		/* The order of these cases is very important. */
		case *pString:
			message = []byte(path)
		case path == "-":
			message, err = ioutil.ReadAll(os.Stdin)
		default:
			message, err = os.ReadFile(path)
		}
		if err != nil {
			readErrs++
			exit = 1
			continue
		}

		t := time.Now()
		digest := api.Sum(message, *pLength)
		var str, delta string

		if *pTime {
			delta = " (" + time.Since(t).String() + ")"
		}

		if *pBase64 {
			str = base64.StdEncoding.EncodeToString(digest)
		} else {
			str = Sprintf("%x", digest)
		}

		if *pString {
			path = "\"" + path + "\""
		} else if !noFormat {
			path = und + vainpath.Clean(path) + zero
		}

		if quiet {
			Println(str)
		} else {
			Println(yell + str + zero + "  " + path + delta)
		}
	}

	if quiet != true {
		if readErrs == 1 {
			Println("1 " + purp + "target is a directory or is otherwise inaccessible." + zero)
		} else if readErrs > 1 {
			Println(readErrs, purp+"targets are directories or are otherwise inaccessible."+zero)
		}
	}
	os.Exit(exit)
}
