package main

import (
	. "github.com/spf13/pflag"
	"os"
)

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
}

func init() {
	BoolVarP(&pHelp, "help", "h", false,
		purp+"print this help menu"+zero+n)

	BoolVarP(&pBase64, "base64", "b", false,
		purp+"render digests in base64"+zero+" (default hex)")

	/* TODO: Implement checksumming from a list of digests. */

	BoolVarP(&pKeyed, "keyed", "K", false,
		purp+"use the first 24 bytes of STDIN for keyed hashing"+zero)

	UintVarP(&pLength, "length", "l", 32,
		purp+"set output digest length in bytes"+zero)

	Bool("no-codes", pNoCodesDefault,
		purp+"print to console w/o formatting codes or simplified"+zero+
			n+purp+"filepaths"+zero)

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

	StringVarP(&pOffset, "offset", "o", "0",
		purp+"XOF index"+zero)

	BoolVar(&pDebug, "debug", false, "")
	CommandLine.MarkHidden("debug")

	/* Order flags alphabetically except for help, which is hoisted to the top. */
	CommandLine.SortFlags = false
	Parse()
	pStrict = pStrict || pRaw || pDebug
}
