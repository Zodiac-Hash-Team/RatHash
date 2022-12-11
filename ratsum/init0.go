//go:build windows

package main

import (
	. "golang.org/x/sys/windows"
	"os"
)

func init() {
	for _, v := range [2]Handle{
		Handle(os.Stdout.Fd()),
		Handle(os.Stderr.Fd()),
	} {
		var mode uint32
		err := GetConsoleMode(v, &mode)
		if err != nil {
			pNoCodesDefault = true
			break
		}
		if mode&ENABLE_VIRTUAL_TERMINAL_PROCESSING == 0 {
			err = SetConsoleMode(v,
				mode|ENABLE_VIRTUAL_TERMINAL_PROCESSING)
			if err != nil {
				pNoCodesDefault = true
				break
			}
		}
	}
	pNoCodes = pNoCodesDefault
}
