# 0 "rv32ui/lui.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "rv32ui/lui.S"
# See LICENSE for license details.

# 1 "./../env/v/riscv_test.h" 1





# 1 "./../env/v/../p/riscv_test.h" 1





# 1 "./../env/v/../p/../encoding.h" 1
# 7 "./../env/v/../p/riscv_test.h" 2
# 7 "./../env/v/riscv_test.h" 2
# 4 "rv32ui/lui.S" 2



# 1 "rv32ui/../rv64ui/lui.S" 1
# See LICENSE for license details.

#*****************************************************************************
# lui.S
#-----------------------------------------------------------------------------

# Test lui instruction.



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
# 12 "rv32ui/../rv64ui/lui.S" 2

.macro init; .endm
.text; .global extra_boot; extra_boot: ret; .global trap_filter; trap_filter: li a0, 0; ret; .global pf_filter; pf_filter: li a0, 0; ret; .global userstart; userstart: init

  #-------------------------------------------------------------
  # Basic tests
  #-------------------------------------------------------------

  test_2: li gp, 2; lui x1, 0x00000; li x7, ((0x0000000000000000) & ((1 << (32 - 1) << 1) - 1)); bne x1, x7, fail;;
  test_3: li gp, 3; lui x1, 0xfffff;sra x1,x1,1; li x7, ((0xfffffffffffff800) & ((1 << (32 - 1) << 1) - 1)); bne x1, x7, fail;;
  test_4: li gp, 4; lui x1, 0x7ffff;sra x1,x1,20; li x7, ((0x00000000000007ff) & ((1 << (32 - 1) << 1) - 1)); bne x1, x7, fail;;
  test_5: li gp, 5; lui x1, 0x80000;sra x1,x1,20; li x7, ((0xfffffffffffff800) & ((1 << (32 - 1) << 1) - 1)); bne x1, x7, fail;;

  test_6: li gp, 6; lui x0, 0x80000; li x7, ((0) & ((1 << (32 - 1) << 1) - 1)); bne x0, x7, fail;;

  bne x0, gp, pass; fail: sll a0, gp, 1; 1:beqz a0, 1b; or a0, a0, 1; scall;; pass: li a0, 1; scall

unimp

  .data
 .pushsection .tohost,"aw",@progbits; .align 6; .global tohost; tohost: .dword 0; .size tohost, 8; .align 6; .global fromhost; fromhost: .dword 0; .size fromhost, 8; .popsection; .align 4; .global begin_signature; begin_signature:

 


# 8 "rv32ui/lui.S" 2
