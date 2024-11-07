	.file	"string.c"
	.option nopic
	.attribute arch, "rv32i2p1_m2p0_a2p1_f2p2_d2p2_zicsr2p0_zifencei2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.text
	.align	2
	.globl	memcpy
	.hidden	memcpy
	.type	memcpy, @function
memcpy:
	or	a5,a0,a1
	or	a5,a5,a2
	andi	a5,a5,3
	add	a3,a0,a2
	beq	a5,zero,.L2
	add	a2,a1,a2
	mv	a5,a0
	bleu	a3,a0,.L12
.L6:
	lbu	a4,0(a1)
	addi	a1,a1,1
	addi	a5,a5,1
	sb	a4,-1(a5)
	bne	a1,a2,.L6
.L7:
	ret
.L2:
	bleu	a3,a0,.L7
	mv	a5,a0
.L5:
	lw	a4,0(a1)
	addi	a5,a5,4
	addi	a1,a1,4
	sw	a4,-4(a5)
	bgtu	a3,a5,.L5
	ret
.L12:
	ret
	.size	memcpy, .-memcpy
	.align	2
	.globl	memset
	.hidden	memset
	.type	memset, @function
memset:
	addi	sp,sp,-16
	or	a5,a0,a2
	sw	s0,8(sp)
	sw	ra,12(sp)
	andi	a5,a5,3
	mv	s0,a0
	add	a4,a0,a2
	beq	a5,zero,.L14
	bleu	a4,a0,.L18
	andi	a1,a1,0xff
	call	memset
.L18:
	lw	ra,12(sp)
	mv	a0,s0
	lw	s0,8(sp)
	addi	sp,sp,16
	jr	ra
.L14:
	andi	a1,a1,255
	slli	a3,a1,8
	add	a3,a3,a1
	slli	a5,a3,16
	add	a3,a3,a5
	bleu	a4,a0,.L18
	mv	a5,a0
.L17:
	addi	a5,a5,4
	sw	a3,-4(a5)
	bgtu	a4,a5,.L17
	lw	ra,12(sp)
	mv	a0,s0
	lw	s0,8(sp)
	addi	sp,sp,16
	jr	ra
	.size	memset, .-memset
	.align	2
	.globl	strlen
	.hidden	strlen
	.type	strlen, @function
strlen:
	lbu	a5,0(a0)
	beq	a5,zero,.L24
	mv	a5,a0
.L23:
	lbu	a4,1(a5)
	addi	a5,a5,1
	bne	a4,zero,.L23
	sub	a0,a5,a0
	ret
.L24:
	li	a0,0
	ret
	.size	strlen, .-strlen
	.align	2
	.globl	strcmp
	.hidden	strcmp
	.type	strcmp, @function
strcmp:
.L28:
	lbu	a5,0(a0)
	addi	a1,a1,1
	addi	a0,a0,1
	lbu	a4,-1(a1)
	beq	a5,zero,.L29
	beq	a5,a4,.L28
.L27:
	sub	a0,a5,a4
	ret
.L29:
	li	a5,0
	j	.L27
	.size	strcmp, .-strcmp
	.align	2
	.globl	memcmp
	.hidden	memcmp
	.type	memcmp, @function
memcmp:
	or	a5,a0,a1
	andi	a5,a5,3
	bne	a5,zero,.L32
	andi	a6,a2,-4
	add	a6,a0,a6
	bgeu	a0,a6,.L32
	mv	a5,a0
	j	.L35
.L34:
	addi	a5,a5,4
	addi	a1,a1,4
	bleu	a6,a5,.L41
.L35:
	lw	a3,0(a5)
	lw	a4,0(a1)
	beq	a3,a4,.L34
.L41:
	sub	a0,a5,a0
	sub	a2,a2,a0
	mv	a0,a5
.L32:
	add	a2,a1,a2
	j	.L36
.L38:
	lbu	a4,0(a1)
	lbu	a5,-1(a0)
	addi	a1,a1,1
	bne	a5,a4,.L42
.L36:
	addi	a0,a0,1
	bne	a1,a2,.L38
	li	a0,0
	ret
.L42:
	sub	a0,a5,a4
	ret
	.size	memcmp, .-memcmp
	.align	2
	.globl	strcpy
	.hidden	strcpy
	.type	strcpy, @function
strcpy:
	mv	a5,a0
.L44:
	lbu	a4,0(a1)
	addi	a5,a5,1
	addi	a1,a1,1
	sb	a4,-1(a5)
	bne	a4,zero,.L44
	ret
	.size	strcpy, .-strcpy
	.align	2
	.globl	atol
	.hidden	atol
	.type	atol, @function
atol:
	lbu	a4,0(a0)
	li	a3,32
	mv	a5,a0
	bne	a4,a3,.L47
.L48:
	lbu	a4,1(a5)
	addi	a5,a5,1
	beq	a4,a3,.L48
.L47:
	li	a3,45
	beq	a4,a3,.L49
	li	a3,43
	beq	a4,a3,.L68
	lbu	a3,0(a5)
	li	a1,0
	beq	a3,zero,.L67
.L54:
	li	a0,0
.L52:
	addi	a5,a5,1
	slli	a4,a0,2
	addi	a2,a3,-48
	lbu	a3,0(a5)
	add	a4,a4,a0
	slli	a4,a4,1
	add	a0,a2,a4
	bne	a3,zero,.L52
	beq	a1,zero,.L46
	neg	a0,a0
	ret
.L68:
	lbu	a3,1(a5)
	li	a1,0
	addi	a5,a5,1
	bne	a3,zero,.L54
.L67:
	li	a0,0
.L46:
	ret
.L49:
	lbu	a3,1(a5)
	li	a1,1
	addi	a5,a5,1
	bne	a3,zero,.L54
	li	a0,0
	j	.L46
	.size	atol, .-atol
	.ident	"GCC: () 12.2.0"
