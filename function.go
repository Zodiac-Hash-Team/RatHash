package main

import "hash/crc32"

// N.B.: This project is currently InDev.
/* This file is the reference Go implementation of the NAME algorithm as
contrived by the original developer. © 2021 Matthew R Bonnette. The author
thanks the developers of the Go Programming Language and the authors of its
respective libraries, especially those utilized herein. */

var msg []byte
var wordlist []uint64
var digest string

/* Performs an initial CRC of the inputted messages to calculate a deterministic
pass count between 1 and 10. CRC32-C was chosen for its low resource overhead,
hardware acceleration, and known reliability in detecting changes in length,
order, and value. This CRC implementation is least-significant byte first, so
truncating to the first digit is most likely to produce an avalanche effect. */
func roundCount(stream []byte) uint32 {
	table := crc32.MakeTable(crc32.Castagnoli)
	sum := crc32.Checksum(stream, table)
	return sum/1e9 + 1 // We can't have it running 0 times, now can we? ;)
}

/* Expands messages by first appending a bit with the value of 1 to the end of
them and then repeatedly encoding them in base64 until their length in bits is
divisible by 64 (the word length). The word length of 64 was chosen to aid in
parallelism; additionally, according to the prime-counting function, 64-bit
values contain approximately 2^64/log(2^64) unique prime values—this was deemed
punishing enough for any computers utilizing this algorithm. */
func messageExpand() {

}

// THIS DESCRIPTION NEEDS FIXING.
/* Compresses a word splice in the expanded message by first treating it as a
64-bit integer and then finding the nearest prime integer lesser than
or equal to itself to mod it by, rendering a usually much smaller number; this
value is then XORed to produce a much word much greater in value which is
reintroduced into a newly redefined wordlist (to be processed in this way as
many times as roundCount() returns). */
func compressWord() {

}
