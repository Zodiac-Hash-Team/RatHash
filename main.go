package main

import (
	"bufio"
	"fmt"
	"os"
)

/* The code in this file is what allows this hash function to be used as a program:
It handles commandline flags and arguments, processing files as required by the
commandline operator. It also enables the printing of a help menu. */

var err error
var exit int

func main() {
	var readErrs int
	paths := os.Args
	/* Will print the help menu and exit the program if no other arguments are given. */
	if len(paths) == 1 {
		fmt.Printf("Help...")
		os.Exit(0)
	}
	fmt.Println()
	/* Checks that the requested digest length meets the function's requirements */
	switch length {
	case 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024:
		break
	default:
		fmt.Printf("\033[31mDigest length must be one of the following values:\033[0m\n" +
			"192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024 bits")
		os.Exit(22)
	}
	for dex := range paths {
		if dex == 0 {
			continue
		}
		path := os.Args[dex]
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
		fmt.Printf("    \033[33m%s\033[0m : \033[4m%s\033[0m\n", hash(message, length), path)
	}
	fmt.Println()
	switch {
	case readErrs == 1:
		fmt.Printf("1 target is inaccessible, does it exist?")
	case readErrs > 1:
		fmt.Printf("%d are inaccessible, do they exist?", readErrs)
	}
	os.Exit(exit)
}
