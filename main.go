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

func main() {
	paths := os.Args
	// Will print the help menu and exit the program if no other arguments are given.
	if len(paths) == 1 {
		fmt.Printf("Help...")
		os.Exit(0)
	}
	for index := range paths {
		// Skips the initial argument (this binary) so it doesn't get treated as a path target.
		if index == 0 {
			continue
		}
		path := os.Args[index]
		// Tests for stdin directed at
		switch stdInfo, _ := os.Stdin.Stat(); {
		case stdInfo.Size() > 0 && path == "-": // Doesn't yet work as expected, unfortunately.
			msg = bufio.NewScanner(os.Stdin).Bytes()
		default:
			msg, err = os.ReadFile(path)
			if err != nil {
				fmt.Printf("    Does %s exist?", path)
				continue
			}
		}
		fmt.Printf("    %d : %s\n", roundCount(msg), path)
	}
	fmt.Printf("(Currently prints round count.)")
}
