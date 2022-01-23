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

// Important performance information can be found at:
// http://stackoverflow.com/a/25089720

// POPCNT has a false-dependency bug that causes a performance
// hit. Thus, in bigloop four separate destination registers are
// used to allow intra-loop parallelization, and in loop the
// destination register is cleared (with no practical effect)
// before POPCNT to allow inter-loop parallelization.

TEXT ·popcnt(SB),NOSPLIT,$0 // The name of this function was changed.
	MOVQ src+0(FP), SI
	MOVQ len+8(FP), BX

	XORQ AX, AX

	CMPQ BX, $8
	JB tail

	CMPQ BX, $32
	JB loop

bigloop:
	POPCNTQ -8(SI)(BX*1), R11
	POPCNTQ -16(SI)(BX*1), R10
	POPCNTQ -24(SI)(BX*1), R9
	POPCNTQ -32(SI)(BX*1), R8

	ADDQ R11, AX
	ADDQ R10, AX
	ADDQ R9, AX
	ADDQ R8, AX

	SUBQ $32, BX
	JZ ret

	CMPQ BX, $32
	JAE bigloop

	CMPQ BX, $8
	JB tail

loop:
	XORQ DX, DX
	POPCNTQ -8(SI)(BX*1), DX

	ADDQ DX, AX

	SUBQ $8, BX
	JZ ret

	CMPQ BX, $8
	JAE loop

tail:
	XORQ DX, DX

	CMPQ BX, $4
	JB tail_2

	MOVL -4(SI)(BX*1), DX

	SUBQ $4, BX
	JZ tail_4

tail_2:
	CMPQ BX, $2
	JB tail_3

	SHLQ $16, DX
	ORW -2(SI)(BX*1), DX

	SUBQ $2, BX
	JZ tail_4

tail_3:
	SHLQ $8, DX
	ORB -1(SI)(BX*1), DX

tail_4:
	POPCNTQ DX, DX

	ADDQ DX, AX

ret:
	MOVQ AX, ret+16(FP)
	RET
