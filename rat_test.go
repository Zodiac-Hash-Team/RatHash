package rathash

import (
	"fmt"
	"github.com/zeebo/blake3"
	"github.com/zeebo/xxh3"
	"testing"
)

func BenchmarkRatHash(b *testing.B) {
	d, _ := NewDigest([32]byte{}, [9]byte{})
	msg := make([]byte, b.N)
	b.SetBytes(1)
	b.ReportAllocs()
	b.ResetTimer()
	d.Write(msg)
	d.Sum(nil)
	b.StopTimer()
	d.Reset()
}

func BenchmarkBlake3(b *testing.B) {
	h, msg := blake3.New(), make([]byte, 1<<10)
	b.SetBytes(1 << 10)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
		h.Sum(nil)
	}
	b.StopTimer()
	h.Reset()
}

func BenchmarkName2(b *testing.B) {
	d, _ := NewDigest([32]byte{}, [9]byte{})
	blk := [bytesPerBlock]byte{}
	b.SetBytes(bytesPerBlock)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.primary(uint64(i), blk, bytesPerBlock)
	}
}

func BenchmarkName(b *testing.B) {
	d, _ := NewDigest([32]byte{}, [9]byte{})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.scheduleKey(0)
	}
	b.StopTimer()
	fmt.Printf("%x\n", d.scheduleKey(0))
}

func BenchmarkXXH3(b *testing.B) {
	h := xxh3.New()
	msg := make([]byte, b.N)
	b.SetBytes(1)
	b.ReportAllocs()
	b.ResetTimer()
	h.Write(msg)
	h.Sum(nil)
	b.StopTimer()
	h.Reset()
}
