# 0 "rv32ui/srli.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "rv32ui/srli.S"
# See LICENSE for license details.

# 1 "./../env/p/riscv_test.h" 1





# 1 "./../env/p/../encoding.h" 1
# 7 "./../env/p/riscv_test.h" 2
# 4 "rv32ui/srli.S" 2



# 1 "rv32ui/../rv64ui/srli.S" 1
# See LICENSE for license details.

#*****************************************************************************
# srli.S
#-----------------------------------------------------------------------------

# Test srli instruction.



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
# 12 "rv32ui/../rv64ui/srli.S" 2

.macro init; .endm
.section .text.init; .align 6; .weak stvec_handler; .weak mtvec_handler; .globl _start; _start: j reset_vector; .align 2; trap_vector: csrr t5, mcause; li t6, 0x8; beq t5, t6, write_tohost; li t6, 0x9; beq t5, t6, write_tohost; li t6, 0xb; beq t5, t6, write_tohost; la t5, mtvec_handler; beqz t5, 1f; jr t5; 1: csrr t5, mcause; bgez t5, handle_exception; j other_exception; handle_exception: other_exception: 1: ori gp, gp, 1337; write_tohost: sw gp, tohost, t5; sw zero, tohost + 4, t5; j write_tohost; reset_vector: li x1, 0; li x2, 0; li x3, 0; li x4, 0; li x5, 0; li x6, 0; li x7, 0; li x8, 0; li x9, 0; li x10, 0; li x11, 0; li x12, 0; li x13, 0; li x14, 0; li x15, 0; li x16, 0; li x17, 0; li x18, 0; li x19, 0; li x20, 0; li x21, 0; li x22, 0; li x23, 0; li x24, 0; li x25, 0; li x26, 0; li x27, 0; li x28, 0; li x29, 0; li x30, 0; li x31, 0;; csrr a0, mhartid; 1: bnez a0, 1b; la t0, 1f; csrw mtvec, t0; csrwi 0x744, 0x00000008; .align 2; 1:; la t0, 1f; csrw mtvec, t0; csrwi satp, 0; .align 2; 1:; la t0, 1f; csrw mtvec, t0; li t0, (1 << (31 + (32 / 64) * (53 - 31))) - 1; csrw pmpaddr0, t0; li t0, 0x18 | 0x01 | 0x02 | 0x04; csrw pmpcfg0, t0; .align 2; 1:; csrwi mie, 0; la t0, 1f; csrw mtvec, t0; csrwi medeleg, 0; csrwi mideleg, 0; .align 2; 1:; li gp, 0; la t0, trap_vector; csrw mtvec, t0; li a0, 1; slli a0, a0, 31; bltz a0, 1f; fence; li gp, 1; li a7, 93; li a0, 0; ecall; 1:; la t0, stvec_handler; beqz t0, 1f; csrw stvec, t0; li t0, (1 << 0xd) | (1 << 0xf) | (1 << 0xc) | (1 << 0x0) | (1 << 0x8) | (1 << 0x3); csrw medeleg, t0; 1: csrwi mstatus, 0; init; ; ; la t0, 1f; csrw mepc, t0; csrr a0, mhartid; mret; 1:

  #-------------------------------------------------------------
  # Arithmetic tests
  #-------------------------------------------------------------




  test_2: li gp, 2; li x13, ((0xffffffff80000000) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((0) | (-(((0) >> 11) & 1) << 11));; li x7, ((((0xffffffff80000000) & ((1 << (32 -1) << 1) - 1)) >> (0)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_3: li gp, 3; li x13, ((0xffffffff80000000) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((1) | (-(((1) >> 11) & 1) << 11));; li x7, ((((0xffffffff80000000) & ((1 << (32 -1) << 1) - 1)) >> (1)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_4: li gp, 4; li x13, ((0xffffffff80000000) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((7) | (-(((7) >> 11) & 1) << 11));; li x7, ((((0xffffffff80000000) & ((1 << (32 -1) << 1) - 1)) >> (7)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_5: li gp, 5; li x13, ((0xffffffff80000000) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((14) | (-(((14) >> 11) & 1) << 11));; li x7, ((((0xffffffff80000000) & ((1 << (32 -1) << 1) - 1)) >> (14)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_6: li gp, 6; li x13, ((0xffffffff80000001) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((31) | (-(((31) >> 11) & 1) << 11));; li x7, ((((0xffffffff80000001) & ((1 << (32 -1) << 1) - 1)) >> (31)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;

  test_7: li gp, 7; li x13, ((0xffffffffffffffff) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((0) | (-(((0) >> 11) & 1) << 11));; li x7, ((((0xffffffffffffffff) & ((1 << (32 -1) << 1) - 1)) >> (0)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_8: li gp, 8; li x13, ((0xffffffffffffffff) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((1) | (-(((1) >> 11) & 1) << 11));; li x7, ((((0xffffffffffffffff) & ((1 << (32 -1) << 1) - 1)) >> (1)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_9: li gp, 9; li x13, ((0xffffffffffffffff) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((7) | (-(((7) >> 11) & 1) << 11));; li x7, ((((0xffffffffffffffff) & ((1 << (32 -1) << 1) - 1)) >> (7)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_10: li gp, 10; li x13, ((0xffffffffffffffff) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((14) | (-(((14) >> 11) & 1) << 11));; li x7, ((((0xffffffffffffffff) & ((1 << (32 -1) << 1) - 1)) >> (14)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_11: li gp, 11; li x13, ((0xffffffffffffffff) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((31) | (-(((31) >> 11) & 1) << 11));; li x7, ((((0xffffffffffffffff) & ((1 << (32 -1) << 1) - 1)) >> (31)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;

  test_12: li gp, 12; li x13, ((0x0000000021212121) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((0) | (-(((0) >> 11) & 1) << 11));; li x7, ((((0x0000000021212121) & ((1 << (32 -1) << 1) - 1)) >> (0)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_13: li gp, 13; li x13, ((0x0000000021212121) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((1) | (-(((1) >> 11) & 1) << 11));; li x7, ((((0x0000000021212121) & ((1 << (32 -1) << 1) - 1)) >> (1)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_14: li gp, 14; li x13, ((0x0000000021212121) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((7) | (-(((7) >> 11) & 1) << 11));; li x7, ((((0x0000000021212121) & ((1 << (32 -1) << 1) - 1)) >> (7)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_15: li gp, 15; li x13, ((0x0000000021212121) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((14) | (-(((14) >> 11) & 1) << 11));; li x7, ((((0x0000000021212121) & ((1 << (32 -1) << 1) - 1)) >> (14)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_16: li gp, 16; li x13, ((0x0000000021212121) & ((1 << (32 - 1) << 1) - 1)); srli x14, x13, ((31) | (-(((31) >> 11) & 1) << 11));; li x7, ((((0x0000000021212121) & ((1 << (32 -1) << 1) - 1)) >> (31)) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;

  #-------------------------------------------------------------
  # Source/Destination tests
  #-------------------------------------------------------------

  test_17: li gp, 17; li x11, ((0x80000000) & ((1 << (32 - 1) << 1) - 1)); srli x11, x11, ((7) | (-(((7) >> 11) & 1) << 11));; li x7, ((0x01000000) & ((1 << (32 - 1) << 1) - 1)); bne x11, x7, fail;;

  #-------------------------------------------------------------
  # Bypassing tests
  #-------------------------------------------------------------

  test_18: li gp, 18; li x4, 0; 1: li x1, ((0x80000000) & ((1 << (32 - 1) << 1) - 1)); srli x14, x1, ((7) | (-(((7) >> 11) & 1) << 11)); addi x6, x14, 0; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((0x01000000) & ((1 << (32 - 1) << 1) - 1)); bne x6, x7, fail;;
  test_19: li gp, 19; li x4, 0; 1: li x1, ((0x80000000) & ((1 << (32 - 1) << 1) - 1)); srli x14, x1, ((14) | (-(((14) >> 11) & 1) << 11)); nop; addi x6, x14, 0; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((0x00020000) & ((1 << (32 - 1) << 1) - 1)); bne x6, x7, fail;;
  test_20: li gp, 20; li x4, 0; 1: li x1, ((0x80000001) & ((1 << (32 - 1) << 1) - 1)); srli x14, x1, ((31) | (-(((31) >> 11) & 1) << 11)); nop; nop; addi x6, x14, 0; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((0x00000001) & ((1 << (32 - 1) << 1) - 1)); bne x6, x7, fail;;

  test_21: li gp, 21; li x4, 0; 1: li x1, ((0x80000000) & ((1 << (32 - 1) << 1) - 1)); srli x14, x1, ((7) | (-(((7) >> 11) & 1) << 11)); addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((0x01000000) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_22: li gp, 22; li x4, 0; 1: li x1, ((0x80000000) & ((1 << (32 - 1) << 1) - 1)); nop; srli x14, x1, ((14) | (-(((14) >> 11) & 1) << 11)); addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((0x00020000) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_23: li gp, 23; li x4, 0; 1: li x1, ((0x80000001) & ((1 << (32 - 1) << 1) - 1)); nop; nop; srli x14, x1, ((31) | (-(((31) >> 11) & 1) << 11)); addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((0x00000001) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;

  test_24: li gp, 24; srli x1, x0, ((4) | (-(((4) >> 11) & 1) << 11));; li x7, ((0) & ((1 << (32 - 1) << 1) - 1)); bne x1, x7, fail;;
  test_25: li gp, 25; li x1, ((33) & ((1 << (32 - 1) << 1) - 1)); srli x0, x1, ((10) | (-(((10) >> 11) & 1) << 11));; li x7, ((0) & ((1 << (32 - 1) << 1) - 1)); bne x0, x7, fail;;

  bne x0, gp, pass; fail: fence; 1: beqz gp, 1b; sll gp, gp, 1; or gp, gp, 1; li a7, 93; addi a0, gp, 0; ecall; pass: fence; li gp, 1; li a7, 93; li a0, 0; ecall

unimp

  .data
 .pushsection .tohost,"aw",@progbits; .align 6; .global tohost; tohost: .dword 0; .size tohost, 8; .align 6; .global fromhost; fromhost: .dword 0; .size fromhost, 8; .popsection; .align 4; .global begin_signature; begin_signature:

 

.align 4; .global end_signature; end_signature:
# 8 "rv32ui/srli.S" 2
