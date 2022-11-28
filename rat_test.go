package rathash

import (
	"fmt"
	"math/bits"
	"testing"
	"unsafe"
)

func BenchmarkName(b *testing.B) {
	bytes := make([]byte, 32)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scheduleKey(bytes, 0)
	}
	b.StopTimer()
	fmt.Printf("%x\n", scheduleKey(bytes, 0xffffffffffffffff))
}

func BenchmarkName2(b *testing.B) {
	blk := block{0, make([]byte, bytesPerBlock)}
	d := newDigest([32]byte{}, 0, "")
	b.SetBytes(bytesPerBlock)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.consume(blk, fracPhi)
	}
}

func scheduleKey(key []byte, dex uint64) [4]uint64 {
	dex++
	words := [4]uint64{
		dex * (dex + *(*uint64)(unsafe.Pointer(&key[0]))),
		dex * (dex + *(*uint64)(unsafe.Pointer(&key[8]))),
		dex * (dex + *(*uint64)(unsafe.Pointer(&key[16]))),
		dex * (dex + *(*uint64)(unsafe.Pointer(&key[24])))}

	var jA, jB, jC, jD uint64
	for _, v := range words {
		jA = 0xf1ea5eed
		jB -= v
		jC -= v
		jD -= v
		for i2 := 10; i2 > 0; i2-- {
			jE := jA - bits.RotateLeft64(jB, 7)
			jA = jB ^ bits.RotateLeft64(jC, 13)
			jB = jC + bits.RotateLeft64(jD, 37)
			jC = jD + jE
			jD = jE + jA
		}
	}

	return [4]uint64{jA, jB, jC, jD}
}
