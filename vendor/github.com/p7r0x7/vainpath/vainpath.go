package vainpath

import (
	"path/filepath"
	"strings"
	"unicode"
)

// Copyright © 2022 Matthew R Bonnette. Licensed under a BSD-3-Clause license.

// Clean formats inputs in a way similar to the fish shell's method of shortening paths in
// `fish/functions/prompt_pwd.fish`; it will almost certainly not return valid paths and should be
// used for vanity purposes only.
func Clean(path string) string {
	/* Windows-sensitive */
	segments := strings.Split(filepath.Clean(path), string(filepath.Separator))

	/* Skips final index */
	for i := len(segments) - 2; i >= 0; i-- {
		if len(segments[i]) < 2 {
			continue
		}

		if unicode.IsLetter(rune(segments[i][0])) {
			segments[i] = segments[i][:1]
		} else {
			segments[i] = segments[i][:2]
		}
	}

	return strings.Join(segments, string(filepath.Separator)) /* Windows-sensitive */
}
