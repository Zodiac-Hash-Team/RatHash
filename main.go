package main

import (
	"fmt"
	"github.com/spf13/pflag"
	"io"
	"main/lovecrc"
	"os"
	"runtime"
	"time"
)

/* The code in this file is what allows this hash function to be used as a program:
It handles commandline flags and arguments, processing files as required by the
commandline operator. It also enables the printing of a help menu. */

func main() {
	var (
		err      error
		exit     int
		readErrs int
		message  []byte
	)
	var noFormatting, quiet bool
	for dex := range os.Args {
		switch os.Args[dex] {
		case "--no-formatting":
			noFormatting = true
		case "--quiet":
			quiet = true
		}
	}
	yell, purp, gray, und, zero := "\033[33m", "\033[35m", "\033[90m", "\033[4m", "\033[0m"
	if runtime.GOOS == "windows" || noFormatting || quiet {
		yell, purp, gray, und, zero = "", "", "", "", ""
	}
	pHelp := pflag.BoolP("help", "h", false, purp+"prints this help menu"+zero+"\n")
	pBase64 := pflag.BoolP("base64", "b", false, purp+"renders digest as base64 string"+zero+
		" (default hexadecimal string)")
	pLength := pflag.IntP("length", "l", 192, purp+"sets output digest length in bits"+zero)
	_ = pflag.Bool("no-formatting", false, purp+"prints to console without formatting codes"+zero+
		" (always true on\nwindows)")
	_ = pflag.Bool("quiet", false, purp+"prints ONLY digests or breaking errors"+zero+" (disables formatting)")
	pString := pflag.BoolP("string", "s", false, purp+"process arguments as strings to be hashed"+zero)
	pTime := pflag.BoolP("time", "t", false, purp+"prints time taken to process each message"+zero)
	pVerbose := pflag.BoolP("verbose", "v", false, purp+"prints detailed output regarding each step of the hashing"+
		"\nprocess"+zero+" (includes results from --time)")
	/* Ordered alphabetically except for help, which is anchored to the top. */
	pflag.CommandLine.SortFlags = false
	pflag.Parse()

	/* Prints the help menu and exits the program if no other arguments are given. */
	if pflag.NArg() == 0 || *pHelp {
		fmt.Printf(yell + "The CRC-based cryptographic hashing algorithm." + zero + "\n\n" +
			"Usage:\n" +
			"   lovecrc [-h] [--quiet|no-formatting] <[--]>\n" +
			"           [-b] [--quiet|no-formatting] [-l <int>|l=<int>] <[--]> -|FILE...\n" +
			"           [-b] [-v|t] [--no-formatting] [-l <int>|l=<int>] <[--]> -|FILE...\n" +
			"           [-b] [--quiet|no-formatting] [-l <int>|l=<int>] -s <[--]> STRING...\n" +
			"           [-b] [-v|t] [--no-formatting] [-l <int>|l=<int>] -s <[--]> STRING...\n\n" +
			"Options:\n")
		pflag.PrintDefaults()
		fmt.Printf("\nThanks to spf13's pflag, placement of arguments after `lovecrc` does not matter\n" +
			"unless `--` is specified to signal the end of parsed flag groups. Longform flag\n" +
			"equivalents above. `-` is treated as a reference to STDIN.\n")
		os.Exit(0)
	}

	/* Checks that the requested digest length meets the function's requirements */
	switch *pLength {
	case 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024:
		break
	default:
		fmt.Printf(purp + "Digest length must be one of the following values:" + zero + "\n" +
			"192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024 bits")
		os.Exit(22)
	}
	for dex := range pflag.Args() {
		path := pflag.Arg(dex)
		t := time.Now()
		/* Treats "-" as a reference to stdin if it's named. */
		switch stdInfo, _ := os.Stdin.Stat(); {
		case *pString:
			message = []byte(path)
		case stdInfo.Size() > 0 && path == "-":
			reader := io.LimitReader(os.Stdin, 0x7fffffffffffffff)
			message, err = io.ReadAll(reader)
		case path == "-":
			message = []byte("")
		/* Otherwise, it attempts to read from whichever paths are named. */
		default:
			message, err = os.ReadFile(path)
		}
		if err != nil {
			readErrs++
			exit = 1
			continue
		}
		digest := lovecrc.Hash(message, *pLength)
		delta := time.Since(t).String()

		switch {
		case *pBase64:
			digest.Str = digest.Str64
			fallthrough
		case *pString:
			path = fmt.Sprintf(zero + "\"" + path + "\"")
		}
		switch {
		case quiet:
			fmt.Printf("%s\n", digest.Str)
		case *pVerbose:
			fmt.Printf(purp+"Expanded to"+zero+" "+gray+"%d bytes"+zero+" "+purp+"in"+zero+" (%s)\n"+
				purp+"Compressed block in"+zero+" (%s):\n", digest.ESize, digest.EDelta, digest.CDelta)
			for dex := range digest.Block {
				switch {
				case (dex+1)%8 == 0 || dex == len(digest.Block)-1:
					fmt.Printf(gray+"%x"+zero+"\n", digest.Block[dex])
				default:
					fmt.Printf(gray+"%x"+zero+" ", digest.Block[dex])
				}
			}
			fmt.Printf(purp+"Found primes in"+zero+" (%s):\n", digest.PDelta)
			for dex := range digest.Polys {
				switch {
				case (dex+1)%8 == 0 || dex == len(digest.Polys)-1:
					fmt.Printf(gray+"%x"+zero+"\n", digest.Polys[dex])
				default:
					fmt.Printf(gray+"%x"+zero+" ", digest.Polys[dex])
				}
			}
			fmt.Printf(purp+"Formed digest in"+zero+" (%s):\n"+
				yell+"%s"+zero+" : "+und+"%s"+zero+", (%s)\n", digest.FDelta, digest.Str, path, delta)
		case *pTime:
			fmt.Printf(yell+"%s"+zero+" : "+und+"%s"+zero+", (%s)\n", digest.Str, path, delta)
		default:
			fmt.Printf(yell+"%s"+zero+" : "+und+"%s"+zero+"\n", digest.Str, path)
		}
	}

	if quiet != true {
		switch {
		case readErrs == 1:
			fmt.Printf("1 " + purp + "target is inaccessible, does it exist?" + zero)
		case readErrs > 1:
			fmt.Printf("%d "+purp+"targets are inaccessible, do they exist?"+zero, readErrs)
		}
	}
	os.Exit(exit)
}
