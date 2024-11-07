# 0 "rv32um/mulh.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "rv32um/mulh.S"
# See LICENSE for license details.

#*****************************************************************************
# mulh.S
#-----------------------------------------------------------------------------

# Test mulh instruction.


# 1 "./../env/v/riscv_test.h" 1





# 1 "./../env/v/../p/riscv_test.h" 1





# 1 "./../env/v/../p/../encoding.h" 1
# 7 "./../env/v/../p/riscv_test.h" 2
# 7 "./../env/v/riscv_test.h" 2
# 11 "rv32um/mulh.S" 2
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
# 12 "rv32um/mulh.S" 2

.macro init; .endm
.text; .global extra_boot; extra_boot: ret; .global trap_filter; trap_filter: li a0, 0; ret; .global pf_filter; pf_filter: li a0, 0; ret; .global userstart; userstart: init

  #-------------------------------------------------------------
  # Arithmetic tests
  #-------------------------------------------------------------

  test_2: li gp, 2; li x11, ((0x00000000) & ((1 << (32 - 1) << 1) - 1)); li x12, ((0x00000000) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x11, x12;; li x7, ((0x00000000) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_3: li gp, 3; li x11, ((0x00000001) & ((1 << (32 - 1) << 1) - 1)); li x12, ((0x00000001) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x11, x12;; li x7, ((0x00000000) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_4: li gp, 4; li x11, ((0x00000003) & ((1 << (32 - 1) << 1) - 1)); li x12, ((0x00000007) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x11, x12;; li x7, ((0x00000000) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;

  test_5: li gp, 5; li x11, ((0x00000000) & ((1 << (32 - 1) << 1) - 1)); li x12, ((0xffff8000) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x11, x12;; li x7, ((0x00000000) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_6: li gp, 6; li x11, ((0x80000000) & ((1 << (32 - 1) << 1) - 1)); li x12, ((0x00000000) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x11, x12;; li x7, ((0x00000000) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_7: li gp, 7; li x11, ((0x80000000) & ((1 << (32 - 1) << 1) - 1)); li x12, ((0x00000000) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x11, x12;; li x7, ((0x00000000) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;

  test_30: li gp, 30; li x11, ((0xaaaaaaab) & ((1 << (32 - 1) << 1) - 1)); li x12, ((0x0002fe7d) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x11, x12;; li x7, ((0xffff0081) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_31: li gp, 31; li x11, ((0x0002fe7d) & ((1 << (32 - 1) << 1) - 1)); li x12, ((0xaaaaaaab) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x11, x12;; li x7, ((0xffff0081) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;

  test_32: li gp, 32; li x11, ((0xff000000) & ((1 << (32 - 1) << 1) - 1)); li x12, ((0xff000000) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x11, x12;; li x7, ((0x00010000) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;

  test_33: li gp, 33; li x11, ((0xffffffff) & ((1 << (32 - 1) << 1) - 1)); li x12, ((0xffffffff) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x11, x12;; li x7, ((0x00000000) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_34: li gp, 34; li x11, ((0xffffffff) & ((1 << (32 - 1) << 1) - 1)); li x12, ((0x00000001) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x11, x12;; li x7, ((0xffffffff) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_35: li gp, 35; li x11, ((0x00000001) & ((1 << (32 - 1) << 1) - 1)); li x12, ((0xffffffff) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x11, x12;; li x7, ((0xffffffff) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;

  #-------------------------------------------------------------
  # Source/Destination tests
  #-------------------------------------------------------------

  test_8: li gp, 8; li x11, ((13<<20) & ((1 << (32 - 1) << 1) - 1)); li x12, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); mulh x11, x11, x12;; li x7, ((36608) & ((1 << (32 - 1) << 1) - 1)); bne x11, x7, fail;;
  test_9: li gp, 9; li x11, ((14<<20) & ((1 << (32 - 1) << 1) - 1)); li x12, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); mulh x12, x11, x12;; li x7, ((39424) & ((1 << (32 - 1) << 1) - 1)); bne x12, x7, fail;;
  test_10: li gp, 10; li x11, ((13<<20) & ((1 << (32 - 1) << 1) - 1)); mulh x11, x11, x11;; li x7, ((43264) & ((1 << (32 - 1) << 1) - 1)); bne x11, x7, fail;;

  #-------------------------------------------------------------
  # Bypassing tests
  #-------------------------------------------------------------

  test_11: li gp, 11; li x4, 0; 1: li x1, ((13<<20) & ((1 << (32 - 1) << 1) - 1)); li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x1, x2; addi x6, x14, 0; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((36608) & ((1 << (32 - 1) << 1) - 1)); bne x6, x7, fail;;
  test_12: li gp, 12; li x4, 0; 1: li x1, ((14<<20) & ((1 << (32 - 1) << 1) - 1)); li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x1, x2; nop; addi x6, x14, 0; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((39424) & ((1 << (32 - 1) << 1) - 1)); bne x6, x7, fail;;
  test_13: li gp, 13; li x4, 0; 1: li x1, ((15<<20) & ((1 << (32 - 1) << 1) - 1)); li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x1, x2; nop; nop; addi x6, x14, 0; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((42240) & ((1 << (32 - 1) << 1) - 1)); bne x6, x7, fail;;

  test_14: li gp, 14; li x4, 0; 1: li x1, ((13<<20) & ((1 << (32 - 1) << 1) - 1)); li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x1, x2; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((36608) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_15: li gp, 15; li x4, 0; 1: li x1, ((14<<20) & ((1 << (32 - 1) << 1) - 1)); li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); nop; mulh x14, x1, x2; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((39424) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_16: li gp, 16; li x4, 0; 1: li x1, ((15<<20) & ((1 << (32 - 1) << 1) - 1)); li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); nop; nop; mulh x14, x1, x2; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((42240) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_17: li gp, 17; li x4, 0; 1: li x1, ((13<<20) & ((1 << (32 - 1) << 1) - 1)); nop; li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x1, x2; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((36608) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_18: li gp, 18; li x4, 0; 1: li x1, ((14<<20) & ((1 << (32 - 1) << 1) - 1)); nop; li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); nop; mulh x14, x1, x2; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((39424) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_19: li gp, 19; li x4, 0; 1: li x1, ((15<<20) & ((1 << (32 - 1) << 1) - 1)); nop; nop; li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x1, x2; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((42240) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;

  test_20: li gp, 20; li x4, 0; 1: li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); li x1, ((13<<20) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x1, x2; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((36608) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_21: li gp, 21; li x4, 0; 1: li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); li x1, ((14<<20) & ((1 << (32 - 1) << 1) - 1)); nop; mulh x14, x1, x2; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((39424) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_22: li gp, 22; li x4, 0; 1: li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); li x1, ((15<<20) & ((1 << (32 - 1) << 1) - 1)); nop; nop; mulh x14, x1, x2; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((42240) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_23: li gp, 23; li x4, 0; 1: li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); nop; li x1, ((13<<20) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x1, x2; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((36608) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_24: li gp, 24; li x4, 0; 1: li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); nop; li x1, ((14<<20) & ((1 << (32 - 1) << 1) - 1)); nop; mulh x14, x1, x2; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((39424) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;
  test_25: li gp, 25; li x4, 0; 1: li x2, ((11<<20) & ((1 << (32 - 1) << 1) - 1)); nop; nop; li x1, ((15<<20) & ((1 << (32 - 1) << 1) - 1)); mulh x14, x1, x2; addi x4, x4, 1; li x5, 2; bne x4, x5, 1b; li x7, ((42240) & ((1 << (32 - 1) << 1) - 1)); bne x14, x7, fail;;

  test_26: li gp, 26; li x1, ((31<<26) & ((1 << (32 - 1) << 1) - 1)); mulh x2, x0, x1;; li x7, ((0) & ((1 << (32 - 1) << 1) - 1)); bne x2, x7, fail;;
  test_27: li gp, 27; li x1, ((32<<26) & ((1 << (32 - 1) << 1) - 1)); mulh x2, x1, x0;; li x7, ((0) & ((1 << (32 - 1) << 1) - 1)); bne x2, x7, fail;;
  test_28: li gp, 28; mulh x1, x0, x0;; li x7, ((0) & ((1 << (32 - 1) << 1) - 1)); bne x1, x7, fail;;
  test_29: li gp, 29; li x1, ((33<<20) & ((1 << (32 - 1) << 1) - 1)); li x2, ((34<<20) & ((1 << (32 - 1) << 1) - 1)); mulh x0, x1, x2;; li x7, ((0) & ((1 << (32 - 1) << 1) - 1)); bne x0, x7, fail;;

  bne x0, gp, pass; fail: sll a0, gp, 1; 1:beqz a0, 1b; or a0, a0, 1; scall;; pass: li a0, 1; scall

unimp

  .data
 .pushsection .tohost,"aw",@progbits; .align 6; .global tohost; tohost: .dword 0; .size tohost, 8; .align 6; .global fromhost; fromhost: .dword 0; .size fromhost, 8; .popsection; .align 4; .global begin_signature; begin_signature:

 


