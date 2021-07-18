package main

import (
	"fmt"
	"math/big"
	"os"
)

// Copyright © 2021 Matthew R Bonnette. Openly-licensed under a BSD-3-Clause license.
/* Appends an array of primes to rathash/primes.go. */

func main() {
	str, dex := "", 0
	primes := make([]uint64, 10000)
	one := big.NewInt(1)

	for i := big.NewInt(2); dex < 10000; i.Add(i, one) {
		if i.ProbablyPrime(1) {
			primes[dex] = i.Uint64()
			dex++
		}
	}

	str = fmt.Sprintln("\nvar primes = [10000]uint64{")
	for i := range primes {
		switch i++; {
		case i%12 == 0:
			str += fmt.Sprintf("%d,\n", primes[i-1])
		case i%12 == 1:
			str += fmt.Sprintf("\t%d, ", primes[i-1])
		default:
			str += fmt.Sprintf("%d, ", primes[i-1])
		}
	}
	str += fmt.Sprintln("\n}")

	file, err := os.OpenFile("primes.go", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Failed: primes.go not found and could not be created.")
		os.Exit(1)
	}
	count, err := file.Write([]byte(str))
	if err != nil {
		fmt.Println("Failed: could not append array to file.")
		os.Exit(1)
	}
	fmt.Println(count, "bytes appended successfully to primes.go")
}
