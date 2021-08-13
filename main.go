package main

import (
	"encoding/base64"
	. "fmt"
	"github.com/p7r0x7/rathash/rathash"
	"github.com/p7r0x7/vainpath"
	"github.com/spf13/pflag"
	"os"
	"runtime"
	"time"
)

// Copyright © 2021 Matthew R Bonnette. Licensed under a BSD-3-Clause license.
// The code in this file is what allows this hash function to be used as a program: It handles
// command-line flags and arguments, processing files as required by the command-line operator. It
// also enables the printing of a help menu.

var (
	err      error
	exitCode int
	readErrs int
	noFormat bool
	quiet    bool
	message  []byte
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
	yell, purp, und, zero := "\033[33m", "\033[35m", "\033[4m", "\033[0m"
	if runtime.GOOS == "windows" || noFormat || quiet {
		yell, purp, und, zero = "", "", "", ""
	}

	pHelp := pflag.BoolP("help", "h", false, purp+"prints this help menu"+zero+"\n")

	pBase64 := pflag.BoolP("base64", "b", false, purp+"renders digest as base64 string"+zero+" (default hex string)")

	pLength := pflag.IntP("length", "l", 256, purp+"sets output digest length in bits"+zero)

	pflag.Bool("no-formatting", false, purp+"prints to console without formatting codes"+zero+"\n(always true on windows)")

	pflag.Bool("quiet", false, purp+"prints ONLY digests or breaking errors"+zero+"\n(disables formatting)")

	pString := pflag.BoolP("string", "s", false, purp+"process arguments instead as strings to be hashed"+zero)

	pTime := pflag.BoolP("time", "t", false, purp+"prints time taken to process each message"+zero)

	/* Ordered alphabetically except for help, which is hoisted to the top. */
	pflag.CommandLine.SortFlags = false
	pflag.Parse()

	/* Prints the help menu and exits the program if no other arguments are given. */
	if *pHelp || pflag.NArg() == 0 {
		Println(yell + "The hopefully, eventually, cryptographic hashing algorithm." + zero + "\n\n" +
			"Usage:\n" +
			"  rathash [-h] [--quiet|no-formatting]\n" +
			"          [-b] [--quiet|no-formatting] [-l <int>|l=<int>] -|FILE...\n" +
			"          [-b] [-t] [--no-formatting] [-l <int>|l=<int>] -|FILE...\n" +
			"          [-b] [--quiet|no-formatting] [-l <int>|l=<int>] -s STRING...\n" +
			"          [-b] [-t] [--no-formatting] [-l <int>|l=<int>] -s STRING...\n\n" +
			"Options:")
		pflag.PrintDefaults()
		Println("\nThanks to spf13's pflag, placement of arguments after `rathash` does not matter\n" +
			"unless `--` is specified to signal the end of parsed flag groups. Long-form flag\n" +
			"equivalents above. `-` is treated as a reference to STDIN.")
		os.Exit(0)
	}

	/* Checks that the requested digest length meets the function's requirements */
	if *pLength < 256 || *pLength%64 != 0 {
		Println(purp + "Digest length in bits must be at least 256 and evenly divisible by 64." + zero)
		os.Exit(22)
	}
	for i := range pflag.Args() {
		path := pflag.Arg(i)
		switch stdInfo, _ := os.Stdin.Stat(); {
		/* The order of these cases is very important. */
		case *pString:
			message = []byte(path)
		case path == "-" && stdInfo.Size() > 0:
			message = make([]byte, stdInfo.Size())
			_, err = os.Stdin.Read(message)
		case path == "-":
			message = []byte{}
		default:
			message, err = os.ReadFile(path)
		}
		if err != nil {
			readErrs++
			exitCode = 1
			continue
		}

		t := time.Now()
		digest := rathash.Sum(message, *pLength)
		delta := time.Since(t).String()
		str := Sprintf("%0x", digest)
		if *pBase64 {
			str = base64.StdEncoding.EncodeToString(digest)
		}
		if *pString {
			path = Sprint(zero + "\"" + path + "\"")
		} else {
			path = vainpath.Clean(path)
		}
		switch {
		case quiet:
			Println(str)
		case *pTime:
			Println(yell + str + zero + "  " + und + path + zero + ", (" + delta + ")")
		default:
			Println(yell + str + zero + "  " + und + path + zero)
		}
	}

	if quiet != true {
		switch {
		case readErrs == 1:
			Println("1 " + purp + "target is a directory or is otherwise inaccessible." + zero)
		case readErrs > 1:
			Println(readErrs, purp+"targets are directories or are otherwise inaccessible."+zero)
		}
	}
	os.Exit(exitCode)
}
