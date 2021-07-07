package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/zeebo/blake3"
	"main/lovecrc"
	"runtime"
	"testing"
	"time"
)

// Helper function
func makeBytes(size int64, b *testing.B) []byte {
	bytes := make([]byte, size)
	written, err := rand.Read(bytes)
	if err != nil || int64(written) != size {
		switch size {
		case 8:
			panic("failed to generate 8B random data")
		case 1024 * 1024 * 64:
			panic("failed to generate 64MiB random data")
		case 1024 * 1024 * 1024:
			panic("failed to generate 1GiB random data")
		}
	}
	b.ResetTimer()
	b.SetBytes(size)
	return bytes
}

func lcrc(name string, size int64) {
	fn := func(b *testing.B) {
		bytes := makeBytes(size, b)
		for dex := 0; dex < b.N; dex++ {
			_ = lovecrc.Hash(&bytes, 192)
		}
	}
	r := testing.Benchmark(fn)
	speed := float64(r.Bytes*int64(r.N)) / float64(r.T.Nanoseconds()) * 1e3
	usage := float64(r.AllocedBytesPerOp()) / 1e6
	fmt.Printf(name+"      %7.2fMB/s      %7.2fMB/op\n", speed, usage)
}

/* SHA-256 is faster only on ARM, SHA-512 is faster on most other architectures. */
func sha2(name string, size int64) {
	fn := func(b *testing.B) {
		bytes := makeBytes(size, b)
		switch runtime.GOARCH {
		case "arm64":
			for dex := 0; dex < b.N; dex++ {
				_ = sha256.Sum256(bytes)
			}
		default:
			for dex := 0; dex < b.N; dex++ {
				_ = sha512.Sum512(bytes)
			}
		}
	}
	r := testing.Benchmark(fn)
	speed := float64(r.Bytes*int64(r.N)) / float64(r.T.Nanoseconds()) * 1e3
	usage := float64(r.AllocedBytesPerOp()) / 1e6
	fmt.Printf(name+"      %7.2fMB/s      %7.2fMB/op\n", speed, usage)
}

func b3(name string, size int64) {
	fn := func(b *testing.B) {
		bytes := makeBytes(size, b)
		for dex := 0; dex < b.N; dex++ {
			_ = blake3.Sum512(bytes)
		}
	}
	r := testing.Benchmark(fn)
	speed := float64(r.Bytes*int64(r.N)) / float64(r.T.Nanoseconds()) * 1e3
	usage := float64(r.AllocedBytesPerOp()) / 1e6
	fmt.Printf(name+"      %7.2fMB/s      %7.2fMB/op\n", speed, usage)
}

func main() {
	fmt.Printf("Running benchmarks! ~30sec on midgrade hardware.\n\n" +
		"Function:         Speed:           Usage:\n")

	t := time.Now()
	lcrc("LoveCRC-8B ", 8)
	sha2("SHA2-8B    ", 8)
	b3("BLAKE3-8B  ", 8)
	println()
	lcrc("LoveCRC-64M", 1024*1024*64)
	sha2("SHA2-64M   ", 1024*1024*64)
	b3("BLAKE3-64M ", 1024*1024*64)
	println()
	lcrc("LoveCRC-1G ", 1024*1024*1024)
	sha2("SHA2-1G    ", 1024*1024*1024)
	b3("BLAKE3-1G  ", 1024*1024*1024)

	fmt.Printf("\nFinished in %s on %s/%s\n", time.Since(t), runtime.GOOS, runtime.GOARCH)
}
