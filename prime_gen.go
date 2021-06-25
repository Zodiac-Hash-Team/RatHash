package main

import (
	"fmt"
	"hash/crc32"
	"math/big"
	"os"
)

func main() {
	var str string
	table := crc32.MakeTable(crc32.Castagnoli)
	for crc32.Checksum([]byte(str), table) != 0xf65c30e0 {
		str = ""
		dex := 0
		var ceiling int64 = 65535
		primes := make([]int64, 6542)
		for ceiling != 1 {
			if big.NewInt(ceiling).ProbablyPrime(1) {
				primes[dex] = ceiling
				dex++
			}
			ceiling--
		}
		str = fmt.Sprintf(
			"package main\n" +
				"\n" +
				"/* This is a speedy lookup table that includes all 6542 primes representable by 16-bit\n" +
				"unsigned integers; these values are rendered in descending order for easier matching. */\n" +
				"\n" +
				"var primes = [6542]uint16{\n")
		for dex := range primes {
			prime := primes[dex]
			switch dex++; {
			case dex%8 == 1:
				str += fmt.Sprintf("\t%v, ", prime)
			case dex%8 == 0 || dex == 6542:
				str += fmt.Sprintf("%v,\n", prime)
			default:
				str += fmt.Sprintf("%v, ", prime)
			}
		}
		str += fmt.Sprintf("}\n")
	}
	file, err := os.Create("primes.go")
	if err != nil {
		fmt.Println("Failed: primes.go not created.")
		os.Exit(1)
	}
	count, err := file.WriteString(str)
	if err != nil {
		fmt.Println("Failed: could not write to file.")
		os.Exit(1)
	}
	fmt.Println(count, "bytes written successfully to primes.go with a crc32c of f65c30e0")
}
