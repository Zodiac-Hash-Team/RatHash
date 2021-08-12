package main

import (
	"encoding/binary"
	"fmt"
	"main/rathash"
	"math/big"
)

var (
	iBytes   = make([]byte, 4)
	rBytes   []byte /* Intentionally-ignored race issues make these bytes truly random. */
	integers = map[uint32]*big.Int{}
	random   = map[uint32]*big.Int{}
)

func printMeanBias(hashes map[uint32]*big.Int, ln int) float64 {
	tally := make([]int32, ln)
	for i := range hashes {
		for i2 := ln - 1; i2 >= 0; i2-- {
			if hashes[i].Bit(i2) == 1 {
				tally[i2]++
			}
		}
	}
	var total int32
	for i := range tally {
		tally[i] = tally[i] - int32(ints>>1)
		if tally[i] < 0 {
			total += tally[i] * -1
		} else {
			total += tally[i]
		}
	}
	return (float64(total) / float64(ln)) / float64(ints>>1) * 100
}

func ratTest() {
	for i := ints; i > 0; i-- {
		binary.BigEndian.PutUint32(iBytes, i)
		integers[i] = big.NewInt(0).SetBytes(rathash.Sum(iBytes, length))
		makeBytes(1024)
		random[i] = big.NewInt(0).SetBytes(rathash.Sum(rBytes, length))
	}
	fmt.Printf("%5.3f%%\n", printMeanBias(integers, length))
	fmt.Printf("%5.3f%%\n", printMeanBias(random, length))
}
