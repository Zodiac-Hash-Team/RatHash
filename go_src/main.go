package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"time"
)

/* The code in this file is what allows this hash function to be used as a program:
It handles commandline flags and arguments, processing files as required by the
commandline operator. It also enables the printing of a help menu. */

func main() {
	var err error
	var exit int
	var message []byte
	length := flag.Int(
		"l", 192, "\033[35moutput digest length in bits\033[0m")
	printTime := flag.Bool(
		"t", false, "\033[35mtime taken to process each message is printed\033[0m")
	flag.Parse()

	/* Prints the help menu and exit the program if no other arguments are given. */
	if flag.NArg() == 0 {
		flag.PrintDefaults()
		os.Exit(0)
	}
	fmt.Println()

	/* Checks that the requested digest length meets the function's requirements */
	switch *length {
	case 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024:
		break
	default:
		fmt.Printf("\033[35mDigest length must be one of the following values:\033[0m\n" +
			"192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024 bits")
		os.Exit(22)
	}

	var readErrs int
	for dex := range flag.Args() {
		path := flag.Arg(dex)
		t1 := time.Now()
		/* Tests for stdin directed at this program and treats "-" as a reference to it if there is. */
		switch stdInfo, _ := os.Stdin.Stat(); {
		case stdInfo.Size() > 0 && path == "-": /* Doesn't yet work as expected, unfortunately. */
			message = bufio.NewScanner(os.Stdin).Bytes()
		/* Otherwise, it attempts to read from whichever paths are named. */
		default:
			message, err = os.ReadFile(path)
			if err != nil {
				readErrs++
				exit = 1
				continue
			}
		}
		fmt.Printf("\033[33m%s\033[0m : \033[4m%s\033[0m\n", hash(message, *length), path)
		if *printTime {
			fmt.Printf("(%s)\n", time.Since(t1).String())
		}
	}
	fmt.Println()

	switch {
	case readErrs == 1:
		fmt.Printf("1 \033[35mtarget is inaccessible, does it exist?\033[0m")
	case readErrs > 1:
		fmt.Printf("%d \033[35mtargets are inaccessible, do they exist?\033[0m", readErrs)
	}
	os.Exit(exit)
}
