# 0 "rv32ui/sb.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "rv32ui/sb.S"
# See LICENSE for license details.

# 1 "./../env/v/riscv_test.h" 1





# 1 "./../env/v/../p/riscv_test.h" 1





# 1 "./../env/v/../p/../encoding.h" 1
# 7 "./../env/v/../p/riscv_test.h" 2
# 7 "./../env/v/riscv_test.h" 2
# 4 "rv32ui/sb.S" 2



# 1 "rv32ui/../rv64ui/sb.S" 1
# See LICENSE for license details.

#*****************************************************************************
# sb.S
#-----------------------------------------------------------------------------

# Test sb instruction.



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
# 12 "rv32ui/../rv64ui/sb.S" 2

.macro init; .endm
.text; .global extra_boot; extra_boot: ret; .global trap_filter; trap_filter: li a0, 0; ret; .global pf_filter; pf_filter: li a0, 0; ret; .global userstart; userstart: init

  #-------------------------------------------------------------
  # Basic tests
  #-------------------------------------------------------------

  test_2: li gp, 2; la x2, tdat; li x1, 0xffffffffffffffaa; la x15, 7f; sb x1, 0(x2); lb x14, 0(x2); j 8f; 7: mv x14, x1; 8:; li x7, ((0xffffffffffffffaa) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_3: li gp, 3; la x2, tdat; li x1, 0x0000000000000000; la x15, 7f; sb x1, 1(x2); lb x14, 1(x2); j 8f; 7: mv x14, x1; 8:; li x7, ((0x0000000000000000) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_4: li gp, 4; la x2, tdat; li x1, 0xffffffffffffefa0; la x15, 7f; sb x1, 2(x2); lh x14, 2(x2); j 8f; 7: mv x14, x1; 8:; li x7, ((0xffffffffffffefa0) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_5: li gp, 5; la x2, tdat; li x1, 0x000000000000000a; la x15, 7f; sb x1, 3(x2); lb x14, 3(x2); j 8f; 7: mv x14, x1; 8:; li x7, ((0x000000000000000a) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;

  # Test with negative offset

  test_6: li gp, 6; la x2, tdat8; li x1, 0xffffffffffffffaa; la x15, 7f; sb x1, -3(x2); lb x14, -3(x2); j 8f; 7: mv x14, x1; 8:; li x7, ((0xffffffffffffffaa) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_7: li gp, 7; la x2, tdat8; li x1, 0x0000000000000000; la x15, 7f; sb x1, -2(x2); lb x14, -2(x2); j 8f; 7: mv x14, x1; 8:; li x7, ((0x0000000000000000) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_8: li gp, 8; la x2, tdat8; li x1, 0xffffffffffffffa0; la x15, 7f; sb x1, -1(x2); lb x14, -1(x2); j 8f; 7: mv x14, x1; 8:; li x7, ((0xffffffffffffffa0) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_9: li gp, 9; la x2, tdat8; li x1, 0x000000000000000a; la x15, 7f; sb x1, 0(x2); lb x14, 0(x2); j 8f; 7: mv x14, x1; 8:; li x7, ((0x000000000000000a) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;

  # Test with a negative base

  test_10: li gp, 10; la x1, tdat9; li x2, 0x12345678; addi x4, x1, -32; sb x2, 32(x4); lb x5, 0(x1);; li x7, ((0x78) & ((1 << (32 - 1) << 1) - 1)); bne x5, x7, fail;







  # Test with unaligned base

  test_11: li gp, 11; la x1, tdat9; li x2, 0x00003098; addi x1, x1, -6; sb x2, 7(x1); la x4, tdat10; lb x5, 0(x4);; li x7, ((0xffffffffffffff98) & ((1 << (32 - 1) << 1) - 1)); bne x5, x7, fail;
# 53 "rv32ui/../rv64ui/sb.S"
  #-------------------------------------------------------------
  # Bypassing tests
  #-------------------------------------------------------------

  test_12: li gp, 12; li x4, 0; 1: li x13, 0xffffffffffffffdd; la x12, tdat; sb x13, 0(x12); lb x14, 0(x12); li x7, 0xffffffffffffffdd; bne x14, x7, fail; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b;
  test_13: li gp, 13; li x4, 0; 1: li x13, 0xffffffffffffffcd; la x12, tdat; nop; sb x13, 1(x12); lb x14, 1(x12); li x7, 0xffffffffffffffcd; bne x14, x7, fail; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b;
  test_14: li gp, 14; li x4, 0; 1: li x13, 0xffffffffffffffcc; la x12, tdat; nop; nop; sb x13, 2(x12); lb x14, 2(x12); li x7, 0xffffffffffffffcc; bne x14, x7, fail; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b;
  test_15: li gp, 15; li x4, 0; 1: li x13, 0xffffffffffffffbc; nop; la x12, tdat; sb x13, 3(x12); lb x14, 3(x12); li x7, 0xffffffffffffffbc; bne x14, x7, fail; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b;
  test_16: li gp, 16; li x4, 0; 1: li x13, 0xffffffffffffffbb; nop; la x12, tdat; nop; sb x13, 4(x12); lb x14, 4(x12); li x7, 0xffffffffffffffbb; bne x14, x7, fail; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b;
  test_17: li gp, 17; li x4, 0; 1: li x13, 0xffffffffffffffab; nop; nop; la x12, tdat; sb x13, 5(x12); lb x14, 5(x12); li x7, 0xffffffffffffffab; bne x14, x7, fail; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b;

  test_18: li gp, 18; li x4, 0; 1: la x2, tdat; li x1, 0x33; sb x1, 0(x2); lb x14, 0(x2); li x7, 0x33; bne x14, x7, fail; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b;
  test_19: li gp, 19; li x4, 0; 1: la x2, tdat; li x1, 0x23; nop; sb x1, 1(x2); lb x14, 1(x2); li x7, 0x23; bne x14, x7, fail; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b;
  test_20: li gp, 20; li x4, 0; 1: la x2, tdat; li x1, 0x22; nop; nop; sb x1, 2(x2); lb x14, 2(x2); li x7, 0x22; bne x14, x7, fail; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b;
  test_21: li gp, 21; li x4, 0; 1: la x2, tdat; nop; li x1, 0x12; sb x1, 3(x2); lb x14, 3(x2); li x7, 0x12; bne x14, x7, fail; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b;
  test_22: li gp, 22; li x4, 0; 1: la x2, tdat; nop; li x1, 0x11; nop; sb x1, 4(x2); lb x14, 4(x2); li x7, 0x11; bne x14, x7, fail; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b;
  test_23: li gp, 23; li x4, 0; 1: la x2, tdat; nop; nop; li x1, 0x01; sb x1, 5(x2); lb x14, 5(x2); li x7, 0x01; bne x14, x7, fail; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b;

  li a0, 0xef
  la a1, tdat
  sb a0, 3(a1)

  bne x0, gp, pass; fail: sll a0, gp, 1; 1:beqz a0, 1b; or a0, a0, 1; scall;; pass: li a0, 1; scall

unimp

  .data
 .pushsection .tohost,"aw",@progbits; .align 6; .global tohost; tohost: .dword 0; .size tohost, 8; .align 6; .global fromhost; fromhost: .dword 0; .size fromhost, 8; .popsection; .align 4; .global begin_signature; begin_signature:

 

tdat:
tdat1: .byte 0xef
tdat2: .byte 0xef
tdat3: .byte 0xef
tdat4: .byte 0xef
tdat5: .byte 0xef
tdat6: .byte 0xef
tdat7: .byte 0xef
tdat8: .byte 0xef
tdat9: .byte 0xef
tdat10: .byte 0xef


# 8 "rv32ui/sb.S" 2
