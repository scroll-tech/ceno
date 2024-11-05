# 0 "rv32ui/ma_data.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "rv32ui/ma_data.S"
# See LICENSE for license details.

# 1 "./../env/v/riscv_test.h" 1





# 1 "./../env/v/../p/riscv_test.h" 1





# 1 "./../env/v/../p/../encoding.h" 1
# 7 "./../env/v/../p/riscv_test.h" 2
# 7 "./../env/v/riscv_test.h" 2
# 4 "rv32ui/ma_data.S" 2



# 1 "rv32ui/../rv64ui/ma_data.S" 1
# See LICENSE for license details.

#*****************************************************************************
# ma_data.S
#-----------------------------------------------------------------------------

# Test misaligned ld/st data.
# Based on rv64mi-ma_addr.S



# 1 "./macros/scalar/test_macros.h" 1






#-----------------------------------------------------------------------
# Helper macros
#-----------------------------------------------------------------------
# 20 "./macros/scalar/test_macros.h"
# We use a macro hack to simpify code generation for various numbers
# of bubble cycles.
# 36 "./macros/scalar/test_macros.h"
#-----------------------------------------------------------------------
# RV64UI MACROS
#-----------------------------------------------------------------------

#-----------------------------------------------------------------------
# Tests for instructions with immediate operand
#-----------------------------------------------------------------------
# 92 "./macros/scalar/test_macros.h"
#-----------------------------------------------------------------------
# Tests for an instruction with register operands
#-----------------------------------------------------------------------
# 120 "./macros/scalar/test_macros.h"
#-----------------------------------------------------------------------
# Tests for an instruction with register-register operands
#-----------------------------------------------------------------------
# 214 "./macros/scalar/test_macros.h"
#-----------------------------------------------------------------------
# Test memory instructions
#-----------------------------------------------------------------------
# 347 "./macros/scalar/test_macros.h"
#-----------------------------------------------------------------------
# Test jump instructions
#-----------------------------------------------------------------------
# 376 "./macros/scalar/test_macros.h"
#-----------------------------------------------------------------------
# RV64UF MACROS
#-----------------------------------------------------------------------

#-----------------------------------------------------------------------
# Tests floating-point instructions
#-----------------------------------------------------------------------
# 735 "./macros/scalar/test_macros.h"
#-----------------------------------------------------------------------
# Pass and fail code (assumes test num is in gp)
#-----------------------------------------------------------------------
# 747 "./macros/scalar/test_macros.h"
#-----------------------------------------------------------------------
# Test data section
#-----------------------------------------------------------------------
# 13 "rv32ui/../rv64ui/ma_data.S" 2

.macro init; .endm
.text; .global extra_boot; extra_boot: ret; .global trap_filter; trap_filter: li a0, 0; ret; .global pf_filter; pf_filter: li a0, 0; ret; .global userstart; userstart: init

  la s0, data
# 29 "rv32ui/../rv64ui/ma_data.S"
# within quadword
  li gp, 1; li t1, ((-((0x0201) >> ((16)-1)) << (16)) | ((0x0201) & ((1 << (16))-1))); lh t2, 1(s0); bne t1, t2, fail; 1:
  li gp, 2; li t1, 0x0201; lhu t2, 1(s0); bne t1, t2, fail; 1:
  li gp, 3; li t1, ((-((0x04030201) >> ((32)-1)) << (32)) | ((0x04030201) & ((1 << (32))-1))); lw t2, 1(s0); bne t1, t2, fail; 1:
  li gp, 4; li t1, ((-((0x05040302) >> ((32)-1)) << (32)) | ((0x05040302) & ((1 << (32))-1))); lw t2, 2(s0); bne t1, t2, fail; 1:
  li gp, 5; li t1, ((-((0x06050403) >> ((32)-1)) << (32)) | ((0x06050403) & ((1 << (32))-1))); lw t2, 3(s0); bne t1, t2, fail; 1:
# 50 "rv32ui/../rv64ui/ma_data.S"
 # octword crossing
  li gp, 16; li t1, ((-((0x201f) >> ((16)-1)) << (16)) | ((0x201f) & ((1 << (16))-1))); lh t2, 31(s0); bne t1, t2, fail; 1:
  li gp, 17; li t1, 0x201f; lhu t2, 31(s0); bne t1, t2, fail; 1:
  li gp, 18; li t1, ((-((0x201f1e1d) >> ((32)-1)) << (32)) | ((0x201f1e1d) & ((1 << (32))-1))); lw t2, 29(s0); bne t1, t2, fail; 1:
  li gp, 19; li t1, ((-((0x21201f1e) >> ((32)-1)) << (32)) | ((0x21201f1e) & ((1 << (32))-1))); lw t2, 30(s0); bne t1, t2, fail; 1:
  li gp, 20; li t1, ((-((0x2221201f) >> ((32)-1)) << (32)) | ((0x2221201f) & ((1 << (32))-1))); lw t2, 31(s0); bne t1, t2, fail; 1:
# 71 "rv32ui/../rv64ui/ma_data.S"
 # cacheline crossing
  li gp, 31; li t1, ((-((0x403f) >> ((16)-1)) << (16)) | ((0x403f) & ((1 << (16))-1))); lh t2, 63(s0); bne t1, t2, fail; 1:
  li gp, 32; li t1, 0x403f; lhu t2, 63(s0); bne t1, t2, fail; 1:
  li gp, 33; li t1, ((-((0x403f3e3d) >> ((32)-1)) << (32)) | ((0x403f3e3d) & ((1 << (32))-1))); lw t2, 61(s0); bne t1, t2, fail; 1:
  li gp, 34; li t1, ((-((0x41403f3e) >> ((32)-1)) << (32)) | ((0x41403f3e) & ((1 << (32))-1))); lw t2, 62(s0); bne t1, t2, fail; 1:
  li gp, 35; li t1, ((-((0x4241403f) >> ((32)-1)) << (32)) | ((0x4241403f) & ((1 << (32))-1))); lw t2, 63(s0); bne t1, t2, fail; 1:
# 102 "rv32ui/../rv64ui/ma_data.S"
 # within quadword
  li gp, 46; li t1, ((-((0x8180) >> ((16)-1)) << (16)) | ((0x8180) & ((1 << (16))-1))); sh t1, 1(s0); lh t2, 1(s0); bne t1, t2, fail; 1:
  li gp, 47; li t1, 0x8382; sh t1, 1(s0); lhu t2, 1(s0); bne t1, t2, fail; 1:
  li gp, 48; li t1, ((-((0x87868584) >> ((32)-1)) << (32)) | ((0x87868584) & ((1 << (32))-1))); sw t1, 1(s0); lw t2, 1(s0); bne t1, t2, fail; 1:
  li gp, 49; li t1, ((-((0x8b8a8988) >> ((32)-1)) << (32)) | ((0x8b8a8988) & ((1 << (32))-1))); sw t1, 2(s0); lw t2, 2(s0); bne t1, t2, fail; 1:
  li gp, 50; li t1, ((-((0x8f8e8d8c) >> ((32)-1)) << (32)) | ((0x8f8e8d8c) & ((1 << (32))-1))); sw t1, 3(s0); lw t2, 3(s0); bne t1, t2, fail; 1:
# 123 "rv32ui/../rv64ui/ma_data.S"
 # octword crossing
  li gp, 61; li t1, ((-((0xd5d4) >> ((16)-1)) << (16)) | ((0xd5d4) & ((1 << (16))-1))); sh t1, 31(s0); lh t2, 31(s0); bne t1, t2, fail; 1:
  li gp, 62; li t1, 0xd7d6; sh t1, 31(s0); lhu t2, 31(s0); bne t1, t2, fail; 1:
  li gp, 63; li t1, ((-((0xdbdad9d8) >> ((32)-1)) << (32)) | ((0xdbdad9d8) & ((1 << (32))-1))); sw t1, 29(s0); lw t2, 29(s0); bne t1, t2, fail; 1:
  li gp, 64; li t1, ((-((0xdfdedddc) >> ((32)-1)) << (32)) | ((0xdfdedddc) & ((1 << (32))-1))); sw t1, 30(s0); lw t2, 30(s0); bne t1, t2, fail; 1:
  li gp, 65; li t1, ((-((0xe3e2e1e0) >> ((32)-1)) << (32)) | ((0xe3e2e1e0) & ((1 << (32))-1))); sw t1, 31(s0); lw t2, 31(s0); bne t1, t2, fail; 1:
# 144 "rv32ui/../rv64ui/ma_data.S"
 # cacheline crossing
  li gp, 76; li t1, ((-((0x3534) >> ((16)-1)) << (16)) | ((0x3534) & ((1 << (16))-1))); sh t1, 63(s0); lh t2, 63(s0); bne t1, t2, fail; 1:
  li gp, 77; li t1, 0x3736; sh t1, 63(s0); lhu t2, 63(s0); bne t1, t2, fail; 1:
  li gp, 78; li t1, ((-((0x3b3a3938) >> ((32)-1)) << (32)) | ((0x3b3a3938) & ((1 << (32))-1))); sw t1, 61(s0); lw t2, 61(s0); bne t1, t2, fail; 1:
  li gp, 79; li t1, ((-((0x3f3e3d3c) >> ((32)-1)) << (32)) | ((0x3f3e3d3c) & ((1 << (32))-1))); sw t1, 62(s0); lw t2, 62(s0); bne t1, t2, fail; 1:
  li gp, 80; li t1, ((-((0x43424140) >> ((32)-1)) << (32)) | ((0x43424140) & ((1 << (32))-1))); sw t1, 63(s0); lw t2, 63(s0); bne t1, t2, fail; 1:
# 176 "rv32ui/../rv64ui/ma_data.S"
 # within quadword
  li gp, 91; li t1, 0x9998; li t2, ((-((0x98) >> ((8)-1)) << (8)) | ((0x98) & ((1 << (8))-1))); sh t1, 1(s0); lb t3, 1(s0); bne t2, t3, fail; 1:
  li gp, 92; li t1, 0x9b9a; li t2, ((-((0x9b) >> ((8)-1)) << (8)) | ((0x9b) & ((1 << (8))-1))); sh t1, 1(s0); lb t3, 2(s0); bne t2, t3, fail; 1:
  li gp, 93; li t1, 0x9d9c; li t2, 0x9c; sh t1, 1(s0); lbu t3, 1(s0); bne t2, t3, fail; 1:
  li gp, 94; li t1, 0x9f9e; li t2, 0x9f; sh t1, 1(s0); lbu t3, 2(s0); bne t2, t3, fail; 1:
  li gp, 95; li t1, 0xa3a2a1a0; li t2, ((-((0xa0) >> ((8)-1)) << (8)) | ((0xa0) & ((1 << (8))-1))); sw t1, 1(s0); lb t3, 1(s0); bne t2, t3, fail; 1:
  li gp, 96; li t1, 0xa7a6a5a4; li t2, 0xa5; sw t1, 2(s0); lbu t3, 3(s0); bne t2, t3, fail; 1:
  li gp, 97; li t1, 0xabaaa9a8; li t2, ((-((0xaaa9) >> ((16)-1)) << (16)) | ((0xaaa9) & ((1 << (16))-1))); sw t1, 3(s0); lh t3, 4(s0); bne t2, t3, fail; 1:
  li gp, 98; li t1, 0xafaeadac; li t2, 0xafae; sw t1, 3(s0); lhu t3, 5(s0); bne t2, t3, fail; 1:
# 196 "rv32ui/../rv64ui/ma_data.S"
 # octword crossing
  li gp, 106; li t1, 0xe9e8; li t2, ((-((0xe8) >> ((8)-1)) << (8)) | ((0xe8) & ((1 << (8))-1))); sh t1, 31(s0); lb t3, 31(s0); bne t2, t3, fail; 1:
  li gp, 107; li t1, 0xebea; li t2, ((-((0xeb) >> ((8)-1)) << (8)) | ((0xeb) & ((1 << (8))-1))); sh t1, 31(s0); lb t3, 32(s0); bne t2, t3, fail; 1:
  li gp, 108; li t1, 0xedec; li t2, 0xec; sh t1, 31(s0); lbu t3, 31(s0); bne t2, t3, fail; 1:
  li gp, 109; li t1, 0xefee; li t2, 0xef; sh t1, 31(s0); lbu t3, 32(s0); bne t2, t3, fail; 1:
  li gp, 110; li t1, 0xf3f2f1f0; li t2, ((-((0xf0) >> ((8)-1)) << (8)) | ((0xf0) & ((1 << (8))-1))); sw t1, 29(s0); lb t3, 29(s0); bne t2, t3, fail; 1:
  li gp, 111; li t1, 0xf7f6f5f4; li t2, 0xf6; sw t1, 30(s0); lbu t3, 32(s0); bne t2, t3, fail; 1:
  li gp, 112; li t1, 0xfbfaf9f8; li t2, ((-((0xfbfa) >> ((16)-1)) << (16)) | ((0xfbfa) & ((1 << (16))-1))); sw t1, 29(s0); lh t3, 31(s0); bne t2, t3, fail; 1:
  li gp, 113; li t1, 0xfffefdfc; li t2, 0xfdfc; sw t1, 31(s0); lhu t3, 31(s0); bne t2, t3, fail; 1:
# 216 "rv32ui/../rv64ui/ma_data.S"
 # cacheline crossing
  li gp, 121; li t1, 0x4948; li t2, ((-((0x48) >> ((8)-1)) << (8)) | ((0x48) & ((1 << (8))-1))); sh t1, 63(s0); lb t3, 63(s0); bne t2, t3, fail; 1:
  li gp, 122; li t1, 0x4b4a; li t2, ((-((0x4b) >> ((8)-1)) << (8)) | ((0x4b) & ((1 << (8))-1))); sh t1, 63(s0); lb t3, 64(s0); bne t2, t3, fail; 1:
  li gp, 123; li t1, 0x4d4c; li t2, 0x4c; sh t1, 63(s0); lbu t3, 63(s0); bne t2, t3, fail; 1:
  li gp, 124; li t1, 0x4f4e; li t2, 0x4f; sh t1, 63(s0); lbu t3, 64(s0); bne t2, t3, fail; 1:
  li gp, 125; li t1, 0x53525150; li t2, ((-((0x50) >> ((8)-1)) << (8)) | ((0x50) & ((1 << (8))-1))); sw t1, 61(s0); lb t3, 61(s0); bne t2, t3, fail; 1:
  li gp, 126; li t1, 0x57565554; li t2, 0x56; sw t1, 62(s0); lbu t3, 64(s0); bne t2, t3, fail; 1:
  li gp, 127; li t1, 0x5b5a5958; li t2, ((-((0x5b5a) >> ((16)-1)) << (16)) | ((0x5b5a) & ((1 << (16))-1))); sw t1, 61(s0); lh t3, 63(s0); bne t2, t3, fail; 1:
  li gp, 128; li t1, 0x5f5e5d5c; li t2, 0x5d5c; sw t1, 63(s0); lhu t3, 63(s0); bne t2, t3, fail; 1:
# 334 "rv32ui/../rv64ui/ma_data.S"
  bne x0, gp, pass; fail: sll a0, gp, 1; 1:beqz a0, 1b; or a0, a0, 1; scall;; pass: li a0, 1; scall

unimp

  .data
 .pushsection .tohost,"aw",@progbits; .align 6; .global tohost; tohost: .dword 0; .size tohost, 8; .align 6; .global fromhost; fromhost: .dword 0; .size fromhost, 8; .popsection; .align 4; .global begin_signature; begin_signature:

data:
  .align 3

.word 0x03020100
.word 0x07060504
.word 0x0b0a0908
.word 0x0f0e0d0c
.word 0x13121110
.word 0x17161514
.word 0x1b1a1918
.word 0x1f1e1d1c
.word 0x23222120
.word 0x27262524
.word 0x2b2a2928
.word 0x2f2e2d2c
.word 0x33323130
.word 0x37363534
.word 0x3b3a3938
.word 0x3f3e3d3c

.word 0x43424140
.word 0x47464544
.word 0x4b4a4948
.word 0x4f4e4d4c
.word 0x53525150
.word 0x57565554
.word 0x5b5a5958
.word 0x5f5e5d5c
.word 0x63626160
.word 0x67666564
.word 0x6b6a6968
.word 0x6f6e6d6c
.word 0x73727170
.word 0x77767574
.word 0x7b7a7978
.word 0x7f7e7d7c

.fill 0xff, 1, 80


 


# 8 "rv32ui/ma_data.S" 2
