//go:build windows

package main

import (
	. "bytes"
	"os/exec"
)

func init() {
	out, _ := exec.Command("TASKLIST", "/FI", "IMAGENAME eq cmd.exe").Output()
	pNoCodesDefault = Contains(out, []byte("cmd.exe"))
	pNoCodes = pNoCodesDefault
}
