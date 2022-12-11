package main

import (
	. "github.com/spf13/pflag"
	"os"
)

var pLength, pOffset, pNoCodesDefault = uint(0), "", false
var pHelp, pBase64, pKeyed, pNoCodes, pQuiet, pRaw, pStrict, pString, pTime, pDebug bool
var star, yell, purp, und, zero = "", "\033[33m", "\033[35m", "\033[4m", "\033[0m"

func init() {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--no-codes=false":
			pNoCodes = false
		case "--quiet", "--quiet=true":
			pNoCodes, pQuiet = true, true
		case "--no-codes", "--no-codes=true":
			pNoCodes = true
		}
	}
	if pNoCodes {
		yell, purp, und, zero = "", "", "", ""
	}

	BoolVarP(&pHelp, "help", "h", false,
		purp+"print this help menu"+zero+n)

	BoolVarP(&pBase64, "base64", "b", false,
		purp+"render digests in base64"+zero+" (default hex)")

	/* TODO: Implement checksumming from a list of digests. */

	BoolVar(&pDebug, "debug", false, "")
	CommandLine.MarkHidden("debug")

	BoolVarP(&pKeyed, "keyed", "K", false,
		purp+"use the first 24 bytes of STDIN for keyed hashing"+zero)

	UintVarP(&pLength, "length", "l", 32,
		purp+"set output digest length in bytes"+zero)

	Bool("no-codes", pNoCodesDefault,
		purp+"print to console w/o formatting codes or simplified"+zero+
			n+purp+"filepaths"+zero)

	StringVarP(&pOffset, "offset", "o", "0",
		purp+"extensible output starting index (supports signed"+zero+
			n+purp+"integers in base-prefixed binary, octal, hexdecimal, or"+zero+
			n+purp+"decimal representations)"+zero)

	Bool("quiet", false,
		purp+"suppress non-breaking errors and print ONLY digests"+zero+
			n+"(enables --no-codes)")

	BoolVar(&pRaw, "raw", false,
		purp+"sequentially return the unencoded, non-deliminated bytes"+zero+
			n+purp+"of each digest"+zero+" (enables --strict)")

	BoolVar(&pStrict, "strict", false,
		purp+"cause rathash to panic on any error"+zero)

	BoolVarP(&pString, "string", "s", false,
		purp+"process arguments instead as UTF-8 strings to be hashed"+zero)

	BoolVarP(&pTime, "time", "t", false,
		purp+"print time taken to read and hash each message"+zero)

	/* Order flags alphabetically except for help, which is hoisted to the top. */
	CommandLine.SortFlags = false
	Parse()
	pStrict = pStrict || pRaw || pDebug
}
