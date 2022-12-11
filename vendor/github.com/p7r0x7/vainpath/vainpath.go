package vainpath

import (
	. "path/filepath"
	"strings"
	"unicode"
	. "unicode/utf8"
)

// Copyright © 2022 Matthew R Bonnette. Licensed under a BSD-3-Clause license.

const runeLen, runeSelf = "" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" +
	"\x01\x01\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02" +
	"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02" +
	"\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03" +
	"\x04\x04\x04\x04\x04\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
	uint8(194) /* This table aligns with utf8.first. */

// Trim inputs to no more than n runes; the output will end in the tail specified if the input is
// longer than n runes. Inputs are assumed to be valid UTF-8-encoded strings.
func Trim(str, tail string, n int) (ret string) {
	ret = str
	defer func() {
		recover()
		return
	}()

	var t, w int /* Front to back */
	for w := 0; len(tail[w:]) > 0; t++ {
		if c := tail[w]; c < runeSelf {
			w++
		} else {
			w += int(runeLen[c])
		}
	}
	for i := n - t; len(str[w:]) > 0 && i > 0; i-- {
		if c := str[w]; c < runeSelf {
			w++
		} else {
			w += int(runeLen[c])
		}
	}
	trimmed := str[:w]
	for i := t; len(str[w:]) > 0 && i > 0; i-- {
		if c := str[w]; c < runeSelf {
			w++
		} else {
			w += int(runeLen[c])
		}
	}

	if len(str[w:]) == 0 {
		return /* because ret equals str and is shorter than or contains exactly n runes. */
	} else if t >= n {
		if t == n {
			return tail /* because str and tail respectively contain more than and exactly n runes. */
		}
		for w = len(tail); n > 0; n-- { /* Back to front */
			_, t = DecodeLastRuneInString(tail[:w])
			w -= t
		}
		return tail[w:] /* because both str and tail each contain more than n runes. */
	}
	return trimmed + tail /* because str and tail respectively contain more than and less than n runes. */
}

// Simplify formats inputs in a way similar to the fish shell's method of shortening paths in
// 'fish/functions/prompt_pwd.fish' and is properly Windows-sensitive; it will almost certainly not
// return valid paths and should be used for vanity purposes only. Inputs are assumed to be valid
// UTF-8-encoded strings.
func Simplify(path string) (ret string) {
	ret, path = path, Clean(path)
	/* Bytes of ASCII and non-ASCII code points cannot be mistaken for each other. */
	n, dex := len(path), strings.LastIndexByte(path, Separator)+1 /* There will always be more bytes. */
	if n < 4 || dex < 3 {
		// The following already-cleaned paths cannot be any more shortened:
		// a) paths smaller than 4 bytes
		// b) paths without separators (dex of 0)
		// c) paths where the only separator is the first or second character (dex of 1 or 2)
		return path
	}
	defer func() {
		recover()
		return
	}()

	out, prefix, w := strings.Builder{}, path[:dex], 0
	out.Grow(min(n>>3+n-dex, n)) /* Minimizes re-allocation without expensive calculation. */

	if prefix[0] == Separator {
		w++
	}
	for len(prefix[w:]) > 0 {
		r, t := DecodeRuneInString(prefix[w:])
		if w += t; prefix[w] == Separator {
			w++
			continue
		}
		if !unicode.IsLetter(r) {
			if c := prefix[w]; c < runeSelf {
				if w++; c == Separator {
					continue
				}
			} else {
				w += int(runeLen[c])
			}
		}
		out.WriteString(prefix[:w])
		for {
			if c := prefix[w]; c < runeSelf {
				if c == Separator {
					break
				}
				w++ /* Invalid leading bytes begin invalid 1-byte runes. */
			} else {
				w += int(runeLen[c])
			}
		}
		prefix, w = prefix[w:], 1
	}

	out.WriteString(path[dex-w:])
	return out.String()
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
