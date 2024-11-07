	.file	"vm.c"
	.option nopic
	.attribute arch, "rv32i2p1_m2p0_a2p1_f2p2_d2p2_zicsr2p0_zifencei2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.text
	.align	2
	.type	cputstring, @function
cputstring:
	lbu	a1,0(a0)
	beq	a1,zero,.L1
	lla	a3,tohost
	lla	a2,fromhost
.L6:
	lw	a4,0(a3)
	lw	a5,4(a3)
	mv	a6,a1
	addi	a0,a0,1
	or	a4,a4,a5
	li	a7,16842752
	beq	a4,zero,.L3
.L5:
	li	a4,0
	sw	a4,0(a2)
	li	a5,0
	sw	a5,4(a2)
	lw	a4,0(a3)
	lw	a5,4(a3)
	or	a4,a4,a5
	bne	a4,zero,.L5
.L3:
	sw	a6,0(a3)
	sw	a7,4(a3)
	lbu	a1,0(a0)
	bne	a1,zero,.L6
.L1:
	ret
	.size	cputstring, .-cputstring
	.align	2
	.type	terminate, @function
terminate:
	lla	a3,tohost
	lw	a4,0(a3)
	lw	a5,4(a3)
	mv	a6,a0
	srai	a7,a0,31
	or	a4,a4,a5
	beq	a4,zero,.L17
	lla	a2,fromhost
.L19:
	li	a4,0
	sw	a4,0(a2)
	li	a5,0
	sw	a5,4(a2)
	lw	a4,0(a3)
	lw	a5,4(a3)
	or	a4,a4,a5
	bne	a4,zero,.L19
.L17:
	sw	a6,0(a3)
	sw	a7,4(a3)
.L20:
	j	.L20
	.size	terminate, .-terminate
	.align	2
	.globl	wtf
	.hidden	wtf
	.type	wtf, @function
wtf:
	addi	sp,sp,-16
	li	a0,841
	sw	ra,12(sp)
	call	terminate
	.size	wtf, .-wtf
	.align	2
	.globl	printhex
	.hidden	printhex
	.type	printhex, @function
printhex:
	addi	sp,sp,-32
	addi	a2,sp,12
	addi	a4,sp,27
	li	t1,9
	j	.L30
.L37:
	mv	a4,a5
.L30:
	andi	a5,a0,15
	sgtu	a5,a5,t1
	neg	a5,a5
	andi	a5,a5,39
	andi	a3,a0,15
	addi	a5,a5,48
	add	a5,a3,a5
	sb	a5,0(a4)
	slli	a3,a1,28
	srli	a0,a0,4
	addi	a5,a4,-1
	or	a0,a3,a0
	srli	a1,a1,4
	bne	a2,a4,.L37
	lbu	a0,12(sp)
	sb	zero,28(sp)
	beq	a0,zero,.L27
	mv	a1,a2
	lla	a3,tohost
	lla	a2,fromhost
.L35:
	lw	a4,0(a3)
	lw	a5,4(a3)
	mv	a6,a0
	addi	a1,a1,1
	or	a4,a4,a5
	li	a7,16842752
	beq	a4,zero,.L32
.L34:
	li	a4,0
	sw	a4,0(a2)
	li	a5,0
	sw	a5,4(a2)
	lw	a4,0(a3)
	lw	a5,4(a3)
	or	a4,a4,a5
	bne	a4,zero,.L34
.L32:
	lbu	a0,0(a1)
	sw	a6,0(a3)
	sw	a7,4(a3)
	bne	a0,zero,.L35
.L27:
	addi	sp,sp,32
	jr	ra
	.size	printhex, .-printhex
	.section	.rodata.str1.4,"aMS",@progbits,1
	.align	2
.LC0:
	.string	"Assertion failed: addr >= (1UL << 12) && addr < 63 * (1UL << 12)\n"
	.align	2
.LC1:
	.string	"Assertion failed: !(pt[1][addr/(1UL << 12)] & 0x080) && cause == 0xf\n"
	.align	2
.LC2:
	.string	"Assertion failed: node\n"
	.align	2
.LC3:
	.string	"Assertion failed: user_mapping[addr/(1UL << 12)].addr == 0\n"
	.text
	.align	2
	.globl	handle_fault
	.hidden	handle_fault
	.type	handle_fault, @function
handle_fault:
	addi	sp,sp,-48
	li	a5,1
	li	a4,-4096
	sw	a5,12(sp)
	sw	ra,44(sp)
	sw	s0,40(sp)
	sw	s1,36(sp)
	sw	s2,32(sp)
	sw	s3,28(sp)
	sw	s4,24(sp)
	sw	s5,20(sp)
	sw	zero,8(sp)
	add	a3,a0,a4
	li	a5,253952
	bgeu	a3,a5,.L64
	srli	s3,a0,12
	addi	s1,s3,1024
	lla	s2,pt
	slli	a5,s1,2
	add	a5,s2,a5
	lw	a5,0(a5)
	and	s0,a0,a4
	bne	a5,zero,.L65
	lla	a4,freelist_head
	lw	s4,0(a4)
	beq	s4,zero,.L66
	lw	a5,4(s4)
	lw	a3,freelist_tail
	sw	a5,0(a4)
	beq	a5,a3,.L67
.L57:
	addi	a2,sp,12
	addi	a1,sp,8
	mv	a0,s0
	lw	s5,0(s4)
	call	pf_filter
	bne	a0,zero,.L58
	srli	a3,s5,12
	slli	a3,a3,10
	ori	a3,a3,31
.L59:
	slli	a5,s1,2
	add	a5,s2,a5
	ori	a4,a3,192
	sw	a4,0(a5)
 #APP
# 174 "./../env/v/vm.c" 1
	sfence.vma s0
# 0 "" 2
 #NO_APP
	lla	a5,.LANCHOR0
	slli	s3,s3,3
	add	a5,a5,s3
	lw	a4,0(a5)
	bne	a4,zero,.L68
	lw	a4,0(s4)
	li	a1,262144
	sw	a4,0(a5)
	lw	a4,4(s4)
	sw	a4,4(a5)
 #APP
# 179 "./../env/v/vm.c" 1
	csrrs a1, sstatus, a1
# 0 "" 2
 #NO_APP
	li	a5,-4194304
	add	a5,s0,a5
	li	a2,4096
	mv	a4,s0
	add	a2,a5,a2
.L61:
	lw	t1,0(a5)
	lw	a7,4(a5)
	lw	a6,8(a5)
	lw	a0,12(a5)
	sw	t1,0(a4)
	sw	a7,4(a4)
	sw	a6,8(a4)
	sw	a0,12(a4)
	addi	a5,a5,16
	addi	a4,a4,16
	bne	a5,a2,.L61
 #APP
# 181 "./../env/v/vm.c" 1
	csrw sstatus, a1
# 0 "" 2
 #NO_APP
	slli	a5,s1,2
	add	s1,s2,a5
	sw	a3,0(s1)
 #APP
# 184 "./../env/v/vm.c" 1
	sfence.vma s0
# 0 "" 2
# 186 "./../env/v/vm.c" 1
	fence.i
# 0 "" 2
 #NO_APP
.L48:
	lw	ra,44(sp)
	lw	s0,40(sp)
	lw	s1,36(sp)
	lw	s2,32(sp)
	lw	s3,28(sp)
	lw	s4,24(sp)
	lw	s5,20(sp)
	addi	sp,sp,48
	jr	ra
.L65:
	andi	a4,a5,64
	beq	a4,zero,.L69
	andi	a4,a5,128
	bne	a4,zero,.L53
	li	a4,15
	ori	a5,a5,128
	bne	a1,a4,.L53
.L52:
	slli	s1,s1,2
	add	s1,s2,s1
	sw	a5,0(s1)
 #APP
# 157 "./../env/v/vm.c" 1
	sfence.vma s0
# 0 "" 2
 #NO_APP
	j	.L48
.L58:
	lw	a3,0(s4)
	lw	a5,8(sp)
	srli	a3,a3,12
	slli	a3,a3,10
	or	a3,a3,a5
	j	.L59
.L69:
	ori	a5,a5,64
	j	.L52
.L67:
	sw	zero,freelist_tail,a5
	j	.L57
.L64:
	lla	a0,.LC0
	call	cputstring
	li	a0,3
	call	terminate
.L53:
	lla	a0,.LC1
	call	cputstring
	li	a0,3
	call	terminate
.L66:
	lla	a0,.LC2
	call	cputstring
	li	a0,3
	call	terminate
.L68:
	lla	a0,.LC3
	call	cputstring
	li	a0,3
	call	terminate
	.size	handle_fault, .-handle_fault
	.section	.rodata.str1.4
	.align	2
.LC4:
	.string	"Assertion failed: !\"illegal instruction\"\n"
	.align	2
.LC5:
	.string	"Assertion failed: pt[1][addr/(1UL << 12)] & 0x040\n"
	.align	2
.LC6:
	.string	"Assertion failed: pt[1][addr/(1UL << 12)] & 0x080\n"
	.align	2
.LC7:
	.string	"Assertion failed: tf->epc % 4 == 0\n"
	.align	2
.LC8:
	.string	"Assertion failed: !\"unexpected exception\"\n"
	.text
	.align	2
	.globl	handle_trap
	.hidden	handle_trap
	.type	handle_trap, @function
handle_trap:
	addi	sp,sp,-80
	sw	s0,72(sp)
	sw	ra,76(sp)
	sw	s1,68(sp)
	sw	s2,64(sp)
	sw	s3,60(sp)
	sw	s4,56(sp)
	sw	s5,52(sp)
	sw	s6,48(sp)
	sw	s7,44(sp)
	sw	s8,40(sp)
	sw	s9,36(sp)
	sw	s10,32(sp)
	sw	s11,28(sp)
	mv	s0,a0
	call	trap_filter
	bne	a0,zero,.L107
.L71:
	lw	a1,140(s0)
	li	a5,8
	beq	a1,a5,.L108
	li	a5,2
	beq	a1,a5,.L109
	addi	a5,a1,-12
	li	a4,1
	bleu	a5,a4,.L86
	li	a5,15
	bne	a1,a5,.L87
.L86:
	lw	a0,136(s0)
	call	handle_fault
	mv	a0,s0
	lw	s0,72(sp)
	lw	ra,76(sp)
	lw	s1,68(sp)
	lw	s2,64(sp)
	lw	s3,60(sp)
	lw	s4,56(sp)
	lw	s5,52(sp)
	lw	s6,48(sp)
	lw	s7,44(sp)
	lw	s8,40(sp)
	lw	s9,36(sp)
	lw	s10,32(sp)
	lw	s11,28(sp)
	addi	sp,sp,80
	tail	pop_tf
.L109:
	lw	a4,132(s0)
	andi	a5,a4,3
	bne	a5,zero,.L110
 #APP
# 209 "./../env/v/vm.c" 1
	jal a5, 1f; fssr x0; 1:
# 0 "" 2
 #NO_APP
	lw	a4,0(a4)
	lw	a5,0(a5)
	beq	a4,a5,.L111
	li	a0,65
	lla	a1,.LC4
	lla	a3,tohost
	lla	a2,fromhost
.L82:
	lw	a4,0(a3)
	lw	a5,4(a3)
	mv	s2,a0
	addi	a1,a1,1
	or	a4,a4,a5
	li	s3,16842752
	beq	a4,zero,.L83
.L85:
	li	a5,0
	sw	a5,0(a2)
	li	a6,0
	sw	a6,4(a2)
	lw	a4,0(a3)
	lw	a5,4(a3)
	or	a4,a4,a5
	bne	a4,zero,.L85
.L83:
	lbu	a0,0(a1)
	sw	s2,0(a3)
	sw	s3,4(a3)
	bne	a0,zero,.L82
.L106:
	li	a0,3
	call	terminate
.L107:
	mv	a0,s0
	call	pop_tf
	j	.L71
.L111:
	li	a0,1
	call	terminate
.L110:
	lla	a0,.LC7
	call	cputstring
	li	a0,3
	call	terminate
.L108:
	lw	a5,40(s0)
	li	s2,4096
	lla	s5,.LANCHOR0
	sw	a5,12(sp)
	lla	s10,pt
	li	s9,262144
	li	s8,-4194304
	lla	s4,freelist_tail
	lla	s7,freelist_head
	li	s6,258048
.L79:
	srli	a5,s2,12
	slli	s3,a5,3
	add	a4,s5,s3
	lw	a4,0(a4)
	beq	a4,zero,.L73
	addi	a5,a5,1024
	slli	a5,a5,2
	add	a5,s10,a5
	lw	s1,0(a5)
	andi	a5,s1,64
	beq	a5,zero,.L112
 #APP
# 120 "./../env/v/vm.c" 1
	csrrs s11, sstatus, s9
# 0 "" 2
 #NO_APP
	add	s0,s2,s8
	li	a2,4096
	mv	a1,s0
	mv	a0,s2
	call	memcmp
	beq	a0,zero,.L75
	andi	s1,s1,128
	beq	s1,zero,.L113
	li	a3,4096
	mv	a4,s2
	mv	a5,s0
	add	a3,s2,a3
.L77:
	lw	a6,0(a4)
	lw	a0,4(a4)
	lw	a1,8(a4)
	lw	a2,12(a4)
	sw	a6,0(a5)
	sw	a0,4(a5)
	sw	a1,8(a5)
	sw	a2,12(a5)
	addi	a4,a4,16
	addi	a5,a5,16
	bne	a4,a3,.L77
.L75:
	add	a5,s5,s3
 #APP
# 125 "./../env/v/vm.c" 1
	csrw sstatus, s11
# 0 "" 2
 #NO_APP
	lw	a4,0(s4)
	sw	zero,0(a5)
	beq	a4,zero,.L114
	sw	a5,4(a4)
	sw	a5,0(s4)
.L73:
	li	a5,4096
	add	s2,s2,a5
	bne	s2,s6,.L79
	lw	a0,12(sp)
	call	terminate
.L114:
	sw	a5,0(s4)
	sw	a5,0(s7)
	j	.L73
.L112:
	lla	a0,.LC5
	call	cputstring
	li	a0,3
	call	terminate
.L87:
	lla	a0,.LC8
	call	cputstring
	j	.L106
.L113:
	lla	a0,.LC6
	call	cputstring
	li	a0,3
	call	terminate
	.size	handle_trap, .-handle_trap
	.section	.rodata.str1.4
	.align	2
.LC9:
	.string	"Assertion failed: !\"unsupported satp mode\"\n"
	.text
	.align	2
	.globl	vm_boot
	.hidden	vm_boot
	.type	vm_boot, @function
vm_boot:
 #APP
# 244 "./../env/v/vm.c" 1
	csrr a5, mhartid
# 0 "" 2
 #NO_APP
	bne	a5,zero,.L126
	lla	a2,pt+4096
	srli	a5,a2,12
	addi	sp,sp,-160
	slli	a5,a5,10
	sw	ra,156(sp)
	sw	s0,152(sp)
	lla	a1,pt
	ori	a5,a5,1
	sw	a5,0(a1)
	li	a5,536870912
	srli	a3,a1,12
	li	a4,-2147483648
	addi	a5,a5,207
	sw	a5,-4(a2)
	or	a5,a3,a4
 #APP
# 273 "./../env/v/vm.c" 1
	csrw satp, a5
# 0 "" 2
# 274 "./../env/v/vm.c" 1
	csrr a3, satp
# 0 "" 2
 #NO_APP
	bne	a5,a3,.L127
	mv	s0,a0
	not	a4,a4
	li	a5,31
 #APP
# 280 "./../env/v/vm.c" 1
	la t0, 1f
	csrrw t0, mtvec, t0
	csrw pmpaddr0, a4
	csrw pmpcfg0, a5
	.align 2
	1: csrw mtvec, t0
# 0 "" 2
 #NO_APP
	lla	a5,trap_entry+2143289344
 #APP
# 289 "./../env/v/vm.c" 1
	csrw stvec, a5
# 0 "" 2
# 290 "./../env/v/vm.c" 1
	csrr a5, mscratch
# 0 "" 2
 #NO_APP
	li	a7,2143289344
	add	a5,a5,a7
 #APP
# 290 "./../env/v/vm.c" 1
	csrw sscratch, a5
# 0 "" 2
 #NO_APP
	li	a5,45056
	addi	a5,a5,256
 #APP
# 291 "./../env/v/vm.c" 1
	csrw medeleg, a5
# 0 "" 2
 #NO_APP
	li	a5,122880
	addi	a5,a5,1536
 #APP
# 297 "./../env/v/vm.c" 1
	csrw mstatus, a5
# 0 "" 2
# 298 "./../env/v/vm.c" 1
	csrw mie, 0
# 0 "" 2
 #NO_APP
	lla	a5,.LANCHOR0+2143289848
	sw	a5,freelist_head,a4
	lla	a5,.LANCHOR0+2143290344
	sw	a5,freelist_tail,a4
	li	t1,524288
	lla	a4,.LANCHOR0+504
	lla	t3,.LANCHOR0+1008
	li	a5,22
	li	a1,0
	addi	t1,t1,63
	addi	a7,a7,8
.L122:
	slli	a2,a1,31
	srli	a3,a5,1
	or	a3,a2,a3
	add	a2,a5,t1
	xor	a5,a3,a5
	add	a6,a4,a7
	slli	a2,a2,12
	slli	a5,a5,5
	sw	a2,0(a4)
	sw	a6,4(a4)
	andi	a5,a5,32
	addi	a4,a4,8
	or	a5,a3,a5
	srli	a1,a1,1
	bne	t3,a4,.L122
	li	a2,144
	li	a1,0
	mv	a0,sp
	sw	zero,.LANCHOR0+1004,a5
	call	memset
	li	a5,-2147483648
	add	s0,s0,a5
	mv	a0,sp
	sw	s0,132(sp)
	call	pop_tf
	lw	ra,156(sp)
	lw	s0,152(sp)
	addi	sp,sp,160
	jr	ra
.L126:
	li	a5,264376320
	li	a2,524288
	addi	a5,a5,-1902
	li	a4,0
	addi	a2,a2,-4
	li	a6,-2147483648
	li	a0,1073741824
	j	.L120
.L128:
 #APP
# 233 "./../env/v/vm.c" 1
	amoadd.w zero, zero, (a3)
# 0 "" 2
 #NO_APP
.L119:
	slli	a1,a4,31
	srli	a3,a5,1
	or	a3,a1,a3
	xor	a5,a5,a3
	slli	a5,a5,30
	and	a1,a0,a5
	srli	a4,a4,1
	mv	a5,a3
	or	a4,a1,a4
.L120:
	and	a3,a5,a2
	andi	a1,a5,1
	add	a3,a3,a6
	bne	a1,zero,.L128
 #APP
# 236 "./../env/v/vm.c" 1
	lw zero, (a3)
# 0 "" 2
 #NO_APP
	j	.L119
.L127:
	lla	a0,.LC9
	call	cputstring
	li	a0,3
	call	terminate
	.size	vm_boot, .-vm_boot
	.hidden	freelist_tail
	.globl	freelist_tail
	.hidden	freelist_head
	.globl	freelist_head
	.hidden	freelist_nodes
	.globl	freelist_nodes
	.hidden	user_mapping
	.globl	user_mapping
	.hidden	pt
	.globl	pt
	.bss
	.align	12
	.set	.LANCHOR0,. + 0
	.type	user_mapping, @object
	.size	user_mapping, 504
user_mapping:
	.zero	504
	.type	freelist_nodes, @object
	.size	freelist_nodes, 504
freelist_nodes:
	.zero	504
	.zero	3088
	.type	pt, @object
	.size	pt, 8192
pt:
	.zero	8192
	.section	.sbss,"aw",@nobits
	.align	2
	.type	freelist_tail, @object
	.size	freelist_tail, 4
freelist_tail:
	.zero	4
	.type	freelist_head, @object
	.size	freelist_head, 4
freelist_head:
	.zero	4
	.ident	"GCC: () 12.2.0"
