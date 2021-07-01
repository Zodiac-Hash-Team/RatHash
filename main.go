package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"main/lovecrc"
	"os"
	"time"
)

/* The code in this file is what allows this hash function to be used as a program:
It handles commandline flags and arguments, processing files as required by the
commandline operator. It also enables the printing of a help menu. */

var (
	err     error
	exit    int
	message []byte
	help    bool
	length  int
	pDelta  bool
)

var rootCmd = &cobra.Command{
	Use:   "lovecrc [flags] [file]...",
	Short: "\033[33mThe CRC-based cryptographic hashing algorithm.\033[0m",
	Run: func(cmd *cobra.Command, args []string) {
		/* Prints the help menu and exits the program if no other arguments are given. */
		if len(args) == 0 {
			_ = cmd.Help()
			os.Exit(0)
		}
		/* Checks that the requested digest length meets the function's requirements */
		switch length {
		case 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024:
			break
		default:
			fmt.Printf("\033[35mDigest length must be one of the following values:\033[0m\n" +
				"192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024 bits")
			os.Exit(22)
		}

		var readErrs int
		for dex := range args {
			path := args[dex]
			start := time.Now()
			/* Treats "-" as a reference to stdin if it's named. */
			switch stdInfo, _ := os.Stdin.Stat(); {
			case stdInfo.Size() > 0 && path == "-":
				reader := io.LimitReader(os.Stdin, 0x7fffffffffffffff)
				message, err = io.ReadAll(reader)
			/* Otherwise, it attempts to read from whichever paths are named. */
			default:
				message, err = os.ReadFile(path)
			}
			if err != nil {
				readErrs++
				exit = 1
				continue
			}

			digest := lovecrc.Hash(message, length)
			delta := time.Since(start).String()
			switch {
			case pDelta:
				fmt.Printf("(%s)\n"+
					"\033[33m%s\033[0m : \033[4m%s\033[0m\n", delta, digest, path)
			default:
				fmt.Printf("\033[33m%s\033[0m : \033[4m%s\033[0m\n", digest, path)
			}
		}

		switch {
		case readErrs == 1:
			fmt.Printf("1 \033[35mtarget is inaccessible, does it exist?\033[0m")
		case readErrs > 1:
			fmt.Printf("%d \033[35mtargets are inaccessible, do they exist?\033[0m", readErrs)
		}
		os.Exit(exit)
	},
}

func init() {
	rootCmd.Flags().BoolVarP(&help, "help", "h", false,
		"\033[35mprints this help menu\033[0m")
	rootCmd.Flags().IntVarP(&length, "length", "l", 192,
		"\033[35moutput digest length in bits\033[0m")
	rootCmd.Flags().BoolVarP(&pDelta, "time", "t", false,
		"\033[35mprints time taken to process each message\033[0m")
}

func main() {
	_ = rootCmd.Execute()
}
