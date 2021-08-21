package main

import (
	"fmt"
	"math/big"
	"os"
)

// Copyright © 2021 Matthew R Bonnette. Openly-licensed under a BSD-3-Clause license.
// Appends an array of primes to caches.go.

func main() {
	const primeCount = 20000
	primes := make([]uint64, primeCount)
	primes[0] = 2

	for i, prime, two := 1, big.NewInt(1), big.NewInt(2); i < primeCount; i++ {
		for prime.Add(prime, two).ProbablyPrime(1) == false {
		}
		primes[i] = prime.Uint64()
	}

	str := fmt.Sprintf("\nvar primes = [%d]uint64{\n", primeCount)
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

	file, err := os.OpenFile("caches.go", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Failed: caches.go not found and could not be created.")
		os.Exit(1)
	}
	count, err := file.Write([]byte(str))
	if err != nil {
		fmt.Println("Failed: could not append array to file.")
		os.Exit(1)
	}
	fmt.Println(count, "bytes appended successfully to caches.go")
}
