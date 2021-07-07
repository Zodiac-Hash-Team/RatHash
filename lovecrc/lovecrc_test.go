package lovecrc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/zeebo/blake3"
	"runtime"
	"testing"
)

// Helper function
func makeBytes(size int64, b *testing.B) []byte {
	b.StopTimer()
	bytes := make([]byte, size)
	n, err := rand.Read(bytes)
	if err != nil || int64(n) != size {
		switch size {
		case 8:
			b.Error("failed to generate 8B random data")
		case 1024 * 1024:
			b.Error("failed to generate 1MiB random data")
		case 1024 * 1024 * 64:
			b.Error("failed to generate 64MiB random data")
		case 1024 * 1024 * 1024:
			b.Error("failed to generate 1GiB random data")
		}
	}
	b.StartTimer()
	b.SetBytes(size)
	return bytes
}

// ============ LoveCRC ===============
func BenchmarkHash_8B(b *testing.B) {
	for i := 0; i < b.N; i++ {
		bytes := makeBytes(8, b)
		_ = Hash(&bytes, 192)
	}
	b.ReportAllocs()
}
func BenchmarkHash_64M(b *testing.B) {
	for i := 0; i < b.N; i++ {
		bytes := makeBytes(1024*1024*64, b)
		_ = Hash(&bytes, 192)
	}
	b.ReportAllocs()
}
func BenchmarkHash_1G(b *testing.B) {
	for i := 0; i < b.N; i++ {
		bytes := makeBytes(1024*1024*1024, b)
		_ = Hash(&bytes, 192)
	}
	b.ReportAllocs()
}

// ============ SHA-2 ==============
/* SHA-256 is faster only on ARM, SHA-512 is faster on most other architectures. */
func BenchmarkSHA2_8B(b *testing.B) {
	switch runtime.GOARCH {
	case "arm64":
		for i := 0; i < b.N; i++ {
			bytes := makeBytes(8, b)
			_ = sha256.Sum256(bytes)
		}
	default:
		for i := 0; i < b.N; i++ {
			bytes := makeBytes(8, b)
			_ = sha512.Sum512(bytes)
		}
	}
	b.ReportAllocs()
}
func BenchmarkSHA2_64M(b *testing.B) {
	switch runtime.GOARCH {
	case "arm64":
		for i := 0; i < b.N; i++ {
			bytes := makeBytes(1024*1024*64, b)
			_ = sha256.Sum256(bytes)
		}
	default:
		for i := 0; i < b.N; i++ {
			bytes := makeBytes(1024*1024*64, b)
			_ = sha512.Sum512(bytes)
		}
	}
	b.ReportAllocs()
}
func BenchmarkSHA2_1G(b *testing.B) {
	switch runtime.GOARCH {
	case "arm64":
		for i := 0; i < b.N; i++ {
			bytes := makeBytes(1024*1024*1024, b)
			_ = sha256.Sum256(bytes)
		}
	default:
		for i := 0; i < b.N; i++ {
			bytes := makeBytes(1024*1024*1024, b)
			_ = sha512.Sum512(bytes)
		}
	}
	b.ReportAllocs()
}

// ============ BLAKE3 ===============
func BenchmarkBLAKE3_8B(b *testing.B) {
	for i := 0; i < b.N; i++ {
		bytes := makeBytes(8, b)
		_ = blake3.Sum512(bytes)
	}
	b.ReportAllocs()
}
func BenchmarkBLAKE3_64M(b *testing.B) {
	for i := 0; i < b.N; i++ {
		bytes := makeBytes(1024*1024*64, b)
		_ = blake3.Sum512(bytes)
	}
	b.ReportAllocs()
}
func BenchmarkBLAKE3_1G(b *testing.B) {
	for i := 0; i < b.N; i++ {
		bytes := makeBytes(1024*1024*1024, b)
		_ = blake3.Sum512(bytes)
	}
	b.ReportAllocs()
}
