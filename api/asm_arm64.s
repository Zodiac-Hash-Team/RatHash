// While the following was not written by Tom Thorogood, the author (Barak Michener) didn't change
// the copyright notice to include himself, so it still gets licensed as follows:

// Copyright (c) 2016, Tom Thorogood.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//     * Neither the name of the Tom Thorogood nor the
//       names of its contributors may be used to endorse or promote products
//       derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "textflag.h"

TEXT ·popcnt(SB), NOSPLIT, $0 // The name of this function was changed.
	MOVD src+0(FP), R1
	MOVD len+8(FP), R2

	PRFM (R1), PLDL1KEEP
	MOVD ZR, R0
	CMP  $8, R2
	BLT  tail

	CMP $128, R2
	BLT loop

bigloop:
	VLD1.P 64(R1), [V16.B16, V17.B16, V18.B16, V19.B16]
	VLD1.P 64(R1), [V20.B16, V21.B16, V22.B16, V23.B16]

	// These instrutions should work -- and are represented by the below WORDs
	// However, Go (as of 1.14) silently treats them as the .B8 versions of the same
	// instructions.
	//
	// This has been fixed with issue https://github.com/golang/go/issues/39445
	// so whenever that version gets released, this can convert back again.

	WORD $0x4E205A00 // VCNT   V16.B16, V0.B16
	WORD $0x4E205A21 // VCNT   V17.B16, V1.B16
	WORD $0x4E205A42 // VCNT   V18.B16, V2.B16
	WORD $0x4E205A63 // VCNT   V19.B16, V3.B16
	WORD $0x4E205A84 // VCNT   V20.B16, V4.B16
	WORD $0x4E205AA9 // VCNT   V21.B16, V9.B16
	WORD $0x4E205ACA // VCNT   V22.B16, V10.B16
	WORD $0x4E205AEB // VCNT   V23.B16, V11.B16


	// Add CNT(V20-23) into V14
	VADD    V4.B16,  V9.B16,  V12.B16
	VADD    V10.B16, V11.B16, V13.B16
	VADD    V12.B16, V13.B16, V14.B16

	// Add CNT(V16-19) into V7
	VADD    V0.B16,  V1.B16,  V5.B16
	VADD    V2.B16,  V3.B16,  V6.B16
	VADD    V5.B16,  V6.B16,  V7.B16

	// Add V7 and V14 into V7
	VADD    V14.B16, V7.B16,  V7.B16

	// Bring V7 down into R3
	VUADDLV V7.B16, V8
	VMOV    V8.H[0], R3

	ADD     R3, R0, R0

	SUB $128, R2
	CMP ZR, R2
	BEQ ret

	CMP $128, R2
	BGE bigloop

	CMP $8, R2
	BLT tail

loop:
	VEOR    V7.B16, V7.B16, V7.B16
	VLD1.P  8(R1), [V16.B8]
	VCNT    V16.B8, V7.B8
	VUADDLV V7.B8, V8
	VMOV    V8.H[0], R3
	ADD     R3, R0, R0

	SUB $8, R2
	CMP ZR, R2
	BEQ ret

	CMP $8, R2
	BGE loop

tail:
	VEOR V9.B16, V9.B16, V9.B16

	CMP $4, R2
	BLT tail_2

	VLD1.P 4(R1), V9.S[0]

	SUB $4, R2
	CMP ZR, R2
	BEQ tail_4

tail_2:
	CMP $2, R2
	BLT tail_3

	VLD1.P 2(R1), V9.H[2]

	SUB $2, R2
	CMP ZR, R2
	BEQ tail_4

tail_3:
	VLD1.P 1(R1), V9.B[6]

tail_4:
	VCNT    V9.B8, V7.B8
	VUADDLV V7.B8, V8
	VMOV    V8.H[0], R3
	ADD     R3, R0, R0

ret:
	MOVD R0, ret+16(FP)
	RET
