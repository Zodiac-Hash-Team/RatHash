package api

import "golang.org/x/sys/cpu"

// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.

var hasPopcntASM = featureCheck()

func featureCheck() int {
	switch {
	/* There is no AVX-512-accelerated ASM for this right now. */
	// case cpu.X86.HasAVX512VPOPCNTDQ:
	//	   return 2
	case cpu.X86.HasPOPCNT:
		return 1
	default:
		return 0
	}
}

//go:noescape
func popcnt(src *byte, len uint64) (ret uint64)
