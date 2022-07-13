package vainpath

import (
	"path/filepath"
	"strings"
	"unicode"
	. "unicode/utf8"
)

// Copyright © 2022 Matthew R Bonnette. Licensed under a BSD-3-Clause license.

// Clean formats inputs in a way similar to the fish shell's method of shortening paths in
// 'fish/functions/prompt_pwd.fish' and is properly Windows-sensitive; it will almost certainly not
// return valid paths and should be used for vanity purposes only. If path is an invalid
// UTF-8-encoded string, it is returned unaltered.
func Clean(path string) string {
	if path == "" || !ValidString(path) {
		return path
	}
	segments := strings.Split(filepath.Clean(path), string(filepath.Separator))

	/* Skips final index */
	for i, v := range segments[:len(segments)-1] {
		if RuneCountInString(v) < 2 {
			continue
		}

		r, w0 := DecodeRuneInString(v)
		if unicode.IsLetter(r) {
			segments[i] = v[:w0]
		} else {
			_, w1 := DecodeRuneInString(v[w0:])
			segments[i] = v[:w0+w1]
		}
	}

	return strings.Join(segments, string(filepath.Separator))
}
