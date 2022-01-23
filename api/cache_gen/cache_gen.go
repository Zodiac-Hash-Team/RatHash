package main

import (
	"fmt"
	"math/big"
	"os"
)

// Copyright © 2021 Matthew R Bonnette. Licensed under the Apache-2.0 license.
// Appends an array of very specific Euclid primes to caches.go.

func main() {
	const cacheSize = 10
	ePrimes := make([]string, cacheSize)
	one, two := big.NewInt(1), big.NewInt(2)
	prime, product, tmp := big.NewInt(1), big.NewInt(2), new(big.Int)
	width := 1024

	for i := 0; i < cacheSize; i++ {
		for product.BitLen() < width {
			for !prime.Add(prime, two).ProbablyPrime(1) {
			}
			product.Mul(product, prime)
		}
		for tmp.Or(product, one); !tmp.ProbablyPrime(20); {
			tmp.Add(tmp, two)
		}
		ePrimes[i] = tmp.Text(16)
		width += 256
	}

	str := fmt.Sprintf("\nvar ePrimes = [%d]*big.Int{\n", cacheSize)
	for i := range ePrimes {
		str += fmt.Sprintln("\tload(\"" + ePrimes[i] + "\"),\n")
		for i2, rem := len(ePrimes[i])>>6, len(ePrimes[i])&63; i2 >= 0; i2-- {

		}
	}
	str += fmt.Sprintln("}")

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
