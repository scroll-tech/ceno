# 0 "./../env/v/entry.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "./../env/v/entry.S"
# 1 "./../env/v/riscv_test.h" 1





# 1 "./../env/v/../p/riscv_test.h" 1





# 1 "./../env/v/../p/../encoding.h" 1
# 7 "./../env/v/../p/riscv_test.h" 2
# 7 "./../env/v/riscv_test.h" 2
# 2 "./../env/v/entry.S" 2
# 15 "./../env/v/entry.S"
  .section ".text.init","ax",@progbits
  .globl _start
  .align 2
_start:
  j handle_reset


  .align 2
nmi_vector:
  j wtf

  .align 2
trap_vector:
  j wtf

handle_reset:
  li x1, 0
  li x2, 0
  li x3, 0
  li x4, 0
  li x5, 0
  li x6, 0
  li x7, 0
  li x8, 0
  li x9, 0
  li x10, 0
  li x11, 0
  li x12, 0
  li x13, 0
  li x14, 0
  li x15, 0
  li x16, 0
  li x17, 0
  li x18, 0
  li x19, 0
  li x20, 0
  li x21, 0
  li x22, 0
  li x23, 0
  li x24, 0
  li x25, 0
  li x26, 0
  li x27, 0
  li x28, 0
  li x29, 0
  li x30, 0
  li x31, 0

  la t0, 1f; csrw mtvec, t0; csrwi 0x744, 0x00000008; .align 2; 1:

  la t0, trap_vector
  csrw mtvec, t0
  la sp, (_end + (1 << 12) * 4) - ((32 / 8) * 36)
  csrr t0, mhartid
  slli t0, t0, 12
  add sp, sp, t0
  csrw mscratch, sp
  call extra_boot
  la a0, userstart
  j vm_boot

  .globl pop_tf
pop_tf:
  lw t0,33*4(a0)
  csrw sepc,t0
  lw x1,1*4(a0)
  lw x2,2*4(a0)
  lw x3,3*4(a0)
  lw x4,4*4(a0)
  lw x5,5*4(a0)
  lw x6,6*4(a0)
  lw x7,7*4(a0)
  lw x8,8*4(a0)
  lw x9,9*4(a0)
  lw x11,11*4(a0)
  lw x12,12*4(a0)
  lw x13,13*4(a0)
  lw x14,14*4(a0)
  lw x15,15*4(a0)
  lw x16,16*4(a0)
  lw x17,17*4(a0)
  lw x18,18*4(a0)
  lw x19,19*4(a0)
  lw x20,20*4(a0)
  lw x21,21*4(a0)
  lw x22,22*4(a0)
  lw x23,23*4(a0)
  lw x24,24*4(a0)
  lw x25,25*4(a0)
  lw x26,26*4(a0)
  lw x27,27*4(a0)
  lw x28,28*4(a0)
  lw x29,29*4(a0)
  lw x30,30*4(a0)
  lw x31,31*4(a0)
  lw a0,10*4(a0)
  sret

  .global trap_entry
  .align 2
trap_entry:
  csrrw sp, sscratch, sp

  # save gprs
  sw x1,1*4(sp)
  sw x3,3*4(sp)
  sw x4,4*4(sp)
  sw x5,5*4(sp)
  sw x6,6*4(sp)
  sw x7,7*4(sp)
  sw x8,8*4(sp)
  sw x9,9*4(sp)
  sw x10,10*4(sp)
  sw x11,11*4(sp)
  sw x12,12*4(sp)
  sw x13,13*4(sp)
  sw x14,14*4(sp)
  sw x15,15*4(sp)
  sw x16,16*4(sp)
  sw x17,17*4(sp)
  sw x18,18*4(sp)
  sw x19,19*4(sp)
  sw x20,20*4(sp)
  sw x21,21*4(sp)
  sw x22,22*4(sp)
  sw x23,23*4(sp)
  sw x24,24*4(sp)
  sw x25,25*4(sp)
  sw x26,26*4(sp)
  sw x27,27*4(sp)
  sw x28,28*4(sp)
  sw x29,29*4(sp)
  sw x30,30*4(sp)
  sw x31,31*4(sp)

  csrrw t0,sscratch,sp
  sw t0,2*4(sp)

  # get sr, epc, badvaddr, cause
  csrr t0,sstatus
  sw t0,32*4(sp)
  csrr t0,sepc
  sw t0,33*4(sp)
  csrr t0,stval
  sw t0,34*4(sp)
  csrr t0,scause
  sw t0,35*4(sp)

  move a0, sp
  j handle_trap
