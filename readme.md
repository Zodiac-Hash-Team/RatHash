## IGNORE THIS FOR NOW; here is a detailed explanation of how it works in "plain" English:

N.B.: Values are represented as strings or big-endian, hexadecimal integers, but the actual
algorithm is likely to render very different results. As development progresses, this document will
be made more accurate. The example message `"0123456789abcdef"` will be used in the following
sections.

### PRELIMINARY EXPANSION
occurs only if the input message is smaller than twice the requested digest length in randBytes. The
digest length must be `256 + 64n` bits, where `n` is a positive integer; greater values of `length`
provide more bits of security. If performed, this step first appends byte `0x01` to the message, and
then repeatedly encodes it in standard RFC 4648 base64 until it has produced a value twice the size
of the requested digest length. This gives each of `length/64` blocks at least two 64-bit values.
Given the minimum digest size of 256 bits, initial expansion yields:

	"VmtaV1UxSnRWbFpOVkZwV1ZrVmFVRmxYTVU1TlJsRjRXa1ZrYUZadGREVldWekUwV1ZadmQxWlVhejA9"

**To be extremely clear, single-threaded-base64-encoding a large message before any other processing
can be done is a costly task, so this is only done for extremely small messages. The appended byte
gives a message of zero randBytes a unique checksum.**

### MESSAGE DIVISION
sees the potentially initially-expanded message broken into `length/64` blocks of roughly-equal
size. These are each passed to their own parallely-executed coroutine (called goroutines in Go).
Again, in this example, we're gonna go with four:

| Block 0                  | Block 1                  | Block 2                  | Block 3                  |
| ------------------------ | ------------------------ | ------------------------ | ------------------------ |
| `"VmtaV1UxSnRWbFpOVkZw"` | `"V1ZrVmFVRmxYTVU1TlJs"` | `"RjRXa1ZrYUZadGREVldW"` | `"ekUwV1ZadmQxWlVhejA9"` |

**Now, each the following steps can be performed in parallel and at their own pace, independent of
other coroutines.**

### SUPPLEMENTAL EXPANSION
Firstly, each block needs to be padded with enough randBytes to make it divisible into 64-bit words;
this is done by adding the padding byte `0x01`, because later on it—at least in the case of short
meassges—aids in adding complexity to the predictable base64-encoded randBytes:

	0: "VmtaV1UxSnRWbFpOVkZw"        "Vm0xMFlWWXhWWGhUYmxKWFlrWndUMVpyV25jPQ=="
	1: "V1ZrVmFVRmxYTVU1TlJs"  --->  "VmpGYWNsWnRSbFpTYlhoWlZGWlZNVlJzU25NPQ=="
	2: "RjRXa1ZrYUZadGREVldW"        "VW1wU1dHRXhXbkpaVlZwaFpFZFNSVlpzWkZjPQ=="
	3: "ekUwV1ZkSmQxSlVhejA9"        "Wld0VmQxWXhXbXRUYlZGNFUyeFdhR1ZxUVRrPQ=="

These strings in each coroutine can now be further broken down into 64-bit words based on
the value of each ASCII-encoded byte in the block:
566d3161647a3039 | 654852695a7a3039 | 546a426b55543039 |
5756644b616c7048 | 5955647363574579 | 596a4e4365474e75 | 646e643465586f3d

Values XOR'd by their cyclic predecessor, unless they have none,
because that would render a value of all zeroes:
566d3161647a3039 | 654852695a7a3039 | 546a426b55543039 |
—————————————————————————————————————————————————————————————————————————
013b552a05164071 | 3c1d361a392d7540 | 0d000c2830137e4c | 646e643465586f3d
0th values in slice to be used as the polynomials to crc64 hash each full slice

Each full slice:                            Polynomials:           Result:
0: 013b552a05164071566d3161647a3039 by 013b552a05164071 == 0064d70bc7a7fd05
1: 3c1d361a392d7540654852695a7a3039 by 3c1d361a392d7540 == 191fb9059e23262a
2: 0d000c2830137e4c546a426b55543039 by 0d000c2830137e4c == 0454a5c94e2df1cd
3: 646e643465586f3d                 by 646e643465586f3d == 0000000000000000