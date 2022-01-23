package api

// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.

const hasPopcntASM = 1

//go:noescape
func popcnt(src *byte, len uint64) (ret uint64)
