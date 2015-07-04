#include "mips-regdef.h"

#define _offset_libc -28595

.text

.set noreorder
.option pic0

.globl func_808_asm
.ent func_808_asm
func_808_asm:
     addiu	sp,sp,-48		// 808
     sw	s2,32(sp)		// 80c
     sb	zero,0(a3)		// 810
     move	s2,a0		// 814
     addiu	a0,a0,4		// 818
     sw	s4,40(sp)		// 81c
     sw	s3,36(sp)		// 820
     move	s4,a2		// 824
     sw	s1,28(sp)		// 828
     sw	s0,24(sp)		// 82c
     move	s3,a3		// 830
     sw	ra,44(sp)		// 834
     jal	func_b1c_c		// 838
     move	s1,a1		// 83c
     lui	v1,0xbfc3		// 840
     addiu	s0,v1,_offset_libc		// 844
     move	a0,s4		// 848
     move	a1,s2		// 84c
     li	a2,296		// 850
     move	a3,zero		// 854
     bnez	v0,__958		// 858
     li	v1,11		// 85c
     li	t7,1		// 860
     jal	memcpy         /* memcpy() */		// 864
     sb	t7,0(s3)		// 868
     li	t6,906		// 86c
     move	a0,s1		// 870
     addiu	a1,s2,906		// 874
     li	a2,5		// 878
     move	a3,zero		// 87c
     jal	memcpy		// 880
     sw	t6,16(sp)		// 884
     lw	t5,16(sp)		// 888
     lw	a0,8(s1)		// 88c
     addiu	t4,t5,5		// 890
     move	a1,zero		// 894
     li	a2,32		// 898
     li	a3,1		// 89c
     jal	memset		// 8a0
     sw	t4,16(sp)		// 8a4
     lw	a0,12(s1)		// 8a8
     move	a1,zero		// 8ac
     li	a2,32		// 8b0
     jal	memset		// 8b4
     li	a3,1		// 8b8
     lw	t3,16(sp)		// 8bc
     lw	a0,8(s1)		// 8c0
     addu	a1,s2,t3		// 8c4
     li	a2,30		// 8c8
     jal	memcpy		// 8cc
     move	a3,zero		// 8d0
     lw	a3,16(sp)		// 8d4
     lw	a0,12(s1)		// 8d8
     addiu	t2,a3,30		// 8dc
     addu	a1,s2,t2		// 8e0
     li	a2,30		// 8e4
     move	a3,zero		// 8e8
     jal	memcpy		// 8ec
     sw	t2,16(sp)		// 8f0
     lw	a2,16(sp)		// 8f4
     addiu	a0,s1,16		// 8f8
     addiu	t1,a2,30		// 8fc
     addu	a1,s2,t1		// 900
     li	a2,16		// 904
     move	a3,zero		// 908
     jal	memcpy		// 90c
     sw	t1,16(sp)		// 910
     lw	a1,16(sp)		// 914
     addiu	a0,s1,49		// 918
     addiu	t0,a1,33		// 91c
     addu	a1,s2,t0		// 920
     li	a2,21		// 924
     move	a3,zero		// 928
     jal	memcpy		// 92c
     sw	t0,16(sp)		// 930
     li	v0,1		// 934
     addiu	a0,s4,286		// 938
     addiu	a1,sp,16		// 93c
     li	a2,2		// 940
     li	a3,2		// 944
     jal	memcmp		// 948
     sw	v0,16(sp)		// 94c
     li	v1,24		// 950
     movz	v1,zero,v0		// 954

	__958:
     lw	ra,44(sp)		// 958
     lw	s4,40(sp)		// 95c
     lw	s3,36(sp)		// 960
     lw	s2,32(sp)		// 964
     lw	s1,28(sp)		// 968
     lw	s0,24(sp)		// 96c
     move	v0,v1		// 970
     jr	ra		// 974
     addiu	sp,sp,48		// 978
.end func_808_asm

.globl func_c14_asm
.ent func_c14_asm
func_c14_asm:
     move	t4,a0		// c14
     move	t3,a1		// c18
     move	t2,a2		// c1c
     move	a1,zero		// c20
     move	a0,a2		// c24

	 __c28:
     addiu	v0,a1,1		// c28
     sb	a1,0(a0)		// c2c
     seh	a1,v0		// c30
     slti	v1,a1,256		// c34
     bnez	v1,__c28		// c38
     addiu	a0,a0,1		// c3c
     sb	zero,256(t2)		// c40
     sb	zero,257(t2)		// c44
     move	v1,zero		// c48
     move	t1,zero		// c4c
     move	t0,zero		// c50

	 __c54:
     addiu	v0,v1,1		// c54
     div	zero,v0,t3		// c58
     teq	t3,zero,0x7		// c5c
     addu	a2,t0,t2		// c60
     addu	v1,v1,t4		// c64
     lbu	t9,0(v1)		// c68
     lbu	a1,0(a2)		// c6c
     addiu	t7,t0,1		// c70
     addu	t8,t9,a1		// c74
     addu	t0,t8,t1		// c78
     andi	t1,t0,0xff		// c7c
     addu	t5,t1,t2		// c80
     lbu	t6,0(t5)		// c84
     seh	t0,t7		// c88
     slti	a0,t0,256		// c8c
     sb	t6,0(a2)		// c90
     sb	a1,0(t5)		// c94
     mfhi	a3		// c98
     bnez	a0,__c54		// c9c
     andi	v1,a3,0xff		// ca0
     jr	ra		// ca4
     nop		// ca8
.end func_c14_asm

.globl func_cac_asm
.ent func_cac_asm
func_cac_asm:
     move	t1,a2		// cac
     move	t3,a1		// cb0
     move	t4,a0		// cb4
     lbu	t0,256(a2)		// cb8
     lbu	a3,257(a2)		// cbc
     blez	a1,__d20		// cc0
     move	t2,zero		// cc4

	__cc8:
     addiu	a2,t0,1		// cc8
     andi	t0,a2,0xff		// ccc
     addu	a1,t0,t1		// cd0
     lbu	t9,0(a1)		// cd4
     addu	a2,t4,t2		// cd8
     addu	a0,t9,a3		// cdc
     andi	a3,a0,0xff		// ce0
     addu	v1,a3,t1		// ce4
     lbu	t5,0(v1)		// ce8
     addiu	t2,t2,1		// cec
     sb	t5,0(a1)		// cf0
     sb	t9,0(v1)		// cf4
     lbu	t8,0(a1)		// cf8
     lbu	t5,0(a2)		// cfc
     addu	t7,t8,t9		// d00
     andi	t6,t7,0xff		// d04
     addu	v0,t6,t1		// d08
     lbu	a0,0(v0)		// d0c
     slt	a1,t2,t3		// d10
     xor	v1,t5,a0		// d14
     bnez	a1,__cc8		// d18
     sb	v1,0(a2)		// d1c

	__d20:
     sb	a3,257(t1)		// d20
     jr	ra		// d24
     sb	t0,256(t1)		// d28
.end func_cac_asm

.globl func_d80_asm
.ent func_d80_asm
func_d80_asm:
     addiu	sp,sp,-72		// d80
     sw	s1,60(sp)		// d84
     sw	s0,56(sp)		// d88
     move	s1,a3		// d8c
     move	s0,a2		// d90
     move	a3,a1		// d94
     li	a2,32		// d98
     sw	ra,64(sp)		// d9c
     jal	func_1b1c_c     /* Only called from here */		// da0
     addiu	a1,sp,24		// da4
     lw	v0,88(sp)		// da8
     move	a2,s0		// dac
     move	a3,s1		// db0
     addiu	a0,sp,24		// db4
     li	a1,32		// db8
     jal	func_d2c_c		// dbc
     sw	v0,16(sp)		// dc0
     lw	ra,64(sp)		// dc4
     lw	s1,60(sp)		// dc8
     lw	s0,56(sp)		// dcc
     jr	ra		// dd0
     addiu	sp,sp,72		// dd4
.end func_d80_asm

.globl func_d2c_asm
.ent func_d2c_asm
func_d2c_asm:
     addiu	sp,sp,-32		// d2c
     sw	s0,16(sp)		// d30
     lw	s0,48(sp)		// d34
     sw	s2,24(sp)		// d38
     sw	s1,20(sp)		// d3c
     move	s2,a3		// d40
     move	s1,a2		// d44
     sw	ra,28(sp)		// d48
     jal	func_c14_c      /* Only called from here */		// d4c
     move	a2,s0		// d50
     move	a0,s1		// d54
     move	a1,s2		// d58
     move	a2,s0		// d5c
     lw	ra,28(sp)		// d60
     lw	s2,24(sp)		// d64
     lw	s1,20(sp)		// d68
     lw	s0,16(sp)		// d6c
     j	func_cac_c       /* Only called from here */		// d70
     addiu	sp,sp,32		// d74
.end func_d2c_asm

.globl func_d78_asm
.ent func_d78_asm
func_d78_asm:
     j	func_d2c_c  		// d78
     nop		// d7c
.end func_d78_asm

.globl func_dd8_asm
.ent func_dd8_asm
func_dd8_asm:
     li	v0,1		// dd8
     move	a3,zero		// ddc
     li	v1,15		// de0
     beq	a1,v0,__e14		// de4
     li	a2,15		// de8

	 __dec:
     sll	a1,v1,0x2		// dec
     addu	v0,a1,a0		// df0
     lw	v1,0(v0)		// df4

	 __df8:
     bnez	v1,__e20		// df8
     addiu	v0,v0,-4		// dfc
     addiu	a2,a2,-1		// e00
     bgezl	a2,__df8		// e04
     lw	v1,0(v0)		// e08

	 __e0c:
     jr	ra		// e0c
     move	v0,a3		// e10

	 __e14:
     li	v1,7		// e14
     b	__dec		// e18
     li	a2,7		// e1c

	 __e20:
     move	a0,v1		// e20
     sll	a3,a2,0x5		// e24
     li	v1,31		// e28
     b	__e3c		// e2c
     li	a1,1		// e30

	 __e34:
     bltz	v1,__e0c		// e34
     nop		// e38

	 __e3c:
     sllv	t0,a1,v1		// e3c
     and	a2,a0,t0		// e40
     beqzl	a2,__e34		// e44
     addiu	v1,v1,-1		// e48
     addu	a3,a3,v1		// e4c
     jr	ra		// e50
     move	v0,a3		// e54
.end func_dd8_asm

.globl func_e58_asm
.ent func_e58_asm
func_e58_asm:
     addiu	a1,a1,28		// e58
     addiu	a0,a0,28		// e5c
     move	t0,zero		// e60
     li	a3,7		// e64
     lw	v1,0(a0)		// e68

	 __e6c:
     lw	t1,0(a1)		// e6c
     addiu	a3,a3,-1		// e70
     sltu	v0,t1,v1		// e74
     sltu	a2,v1,t1		// e78
     addiu	a0,a0,-4		// e7c
     bnez	v0,__ea0		// e80
     addiu	a1,a1,-4		// e84
     bnezl	a2,__eac		// e88
     li	t0,-1		// e8c
     bgezl	a3,__e6c		// e90
     lw	v1,0(a0)		// e94
     jr	ra		// e98
     move	v0,t0		// e9c

	 __ea0:
     li	t0,1		// ea0
     jr	ra		// ea4
     move	v0,t0		// ea8

	 __eac:
     jr	ra		// eac
     move	v0,t0		// eb0
.end func_e58_asm

.globl copy_32_bytes_asm
.ent copy_32_bytes_asm
copy_32_bytes_asm:   /* ptr in a0 gets 32 bytes from ptr in a1 */
     li	v1,7		// eb4

	 __eb8:
     lw	v0,0(a1)		// eb8
     addiu	v1,v1,-1		// ebc
     sw	v0,0(a0)		// ec0
     addiu	a1,a1,4		// ec4
     bgez	v1,__eb8		// ec8
     addiu	a0,a0,4		// ecc
     jr	ra		// ed0
     nop		// ed4
.end copy_32_bytes_asm

.globl clear_memory_asm
.ent clear_memory_asm
clear_memory_asm:
     blez	a1,__ef0		// ed8
     nop		// edc

	 __ee0:
     addiu	a1,a1,-1		// ee0
     sw	zero,0(a0)		// ee4
     bnez	a1,__ee0		// ee8
     addiu	a0,a0,4		// eec

	 __ef0:
     jr	ra		// ef0
     nop		// ef4
.end clear_memory_asm

.globl xor_64_bytes_asm
.ent xor_64_bytes_asm
xor_64_bytes_asm:   /* ptr in a0 gets *a1 xor *a2 for 64 bytes */
     li	a3,15		// ef8

	 __efc:
     lw	t0,0(a1)		// efc
     lw	v1,0(a2)		// f00
     addiu	a3,a3,-1		// f04
     xor	v0,t0,v1		// f08
     sw	v0,0(a0)		// f0c
     addiu	a1,a1,4		// f10
     addiu	a0,a0,4		// f14
     bgez	a3,__efc		// f18
     addiu	a2,a2,4		// f1c
     jr	ra		// f20
     nop		// f24
.end xor_64_bytes_asm

.globl func_f28_asm
.ent func_f28_asm
func_f28_asm:
     move	t1,a0		// f28
     move	t0,a1		// f2c
     move	a3,zero		// f30

	 __f34:
     sll	t2,a3,0x2		// f34
     addu	a2,t2,t0		// f38
     addu	v0,t2,t1		// f3c
     lw	a1,0(v0)		// f40
     lw	v1,0(a2)		// f44
     addiu	a3,a3,1		// f48
     slti	a0,a3,8		// f4c
     sw	v1,0(v0)		// f50
     bnez	a0,__f34		// f54
     sw	a1,0(a2)		// f58
     jr	ra		// f5c
     nop		// f60
.end func_f28_asm

.globl func_f64_asm
.ent func_f64_asm
func_f64_asm:
     slti	t2,a1,0		// f64
     addiu	t0,a1,31		// f68
     movz	t0,a1,t2		// f6c
     sra	t1,t0,0x5		// f70
     move	t2,t1		// f74
     sll	a3,t1,0x5		// f78
     subu	t1,a1,a3		// f7c
     li	a2,1		// f80
     sll	a1,t2,0x2		// f84
     sllv	v0,a2,t1		// f88
     addu	v1,a1,a0		// f8c
     addiu	t3,v0,-1		// f90
     addiu	v1,v1,28		// f94
     li	a2,7		// f98
     addiu	a1,a0,28		// f9c

	 __fa0:
     lw	t4,0(a1)		// fa0
     addiu	a2,a2,-1		// fa4
     sw	t4,0(v1)		// fa8
     addiu	a1,a1,-4		// fac
     bgez	a2,__fa0		// fb0
     addiu	v1,v1,-4		// fb4
     blez	t2,__fdc		// fb8
     li	t5,32		// fbc
     move	v1,a0		// fc0
     move	v0,t2		// fc4

	 __fc8:
     addiu	v0,v0,-1		// fc8
     sw	zero,0(v1)		// fcc
     bnez	v0,__fc8		// fd0
     addiu	v1,v1,4		// fd4
     li	t5,32		// fd8

	 __fdc:
     addiu	t4,t2,8		// fdc
     subu	t0,t5,t1		// fe0
     blez	t4,__1028		// fe4
     move	a3,zero		// fe8
     move	a2,t4		// fec
     move	a1,a0		// ff0

	 __ff4:
     lw	t8,0(a1)		// ff4
     addiu	a2,a2,-1		// ff8
     sllv	t9,t8,t1		// ffc
    or	t7,t9,a3		// 1000
    srlv	t6,t8,t0		// 1004
    sw	t7,0(a1)		// 1008
    and	a3,t6,t3		// 100c
    bnez	a2,__ff4		// 1010
    addiu	a1,a1,4		// 1014
    beqz	a3,__1028		// 1018
    sll	v1,t4,0x2		// 101c
    addu	t3,v1,a0		// 1020
    sw	a3,0(t3)		// 1024

	__1028:
    jr	ra		// 1028
    nop		// 102c
.end func_f64_asm

.globl func_1030_asm
.ent func_1030_asm
func_1030_asm:
    addiu	sp,sp,-48		// 1030
    lui	a3,0xbfc3		// 1034
    sw	s1,20(sp)		// 1038
	la s1, __bss + 0x0320
    sw	s4,32(sp)		// 1040
    sw	s0,16(sp)		// 1044
    move	s4,a0		// 1048
    move	s0,a1		// 104c
    move	a0,s1		// 1050
    li	a1,16		// 1054
    sw	ra,40(sp)		// 1058
    sw	s5,36(sp)		// 105c
    sw	s3,28(sp)		// 1060
    jal	clear_memory		// 1064
    sw	s2,24(sp)		// 1068
    move	a0,s4		// 106c
    jal	clear_memory		// 1070
    li	a1,8		// 1074
    lui	a2,0xbfc3		// 1078
	la s5, __bss + 0x1080
    li	a0,1		// 1080
    sw	a0,0(s4)		// 1084
    li	a1,8		// 1088
    jal	clear_memory		// 108c
    move	a0,s5		// 1090
    lui	v1,0xbfc3		// 1094
    la	s2, __bss + 0x0020 // 1098
    move	a1,s0		// 109c
    jal	copy_32_bytes		// 10a0
    move	a0,s2		// 10a4
    lui	v0,0xbfc3		// 10a8
	la s3, __bss + 0x08a0
	la a1, _data_3400
    jal	copy_32_bytes		// 10b8
    move	a0,s3		// 10bc
    b	__1138		// 10c0
    move	a0,s2		// 10c4

	__10c8:
    move	a0,s3		// 10c8
    jal	func_dd8_c		// 10cc
    li	a1,1		// 10d0
    subu	s0,s0,v0		// 10d4
    move	a0,s2		// 10d8
    bltz	s0,__116c		// 10dc
    move	a1,s3		// 10e0
    move	a0,s1		// 10e4

	__10e8:
    jal	copy_32_bytes		// 10e8
    move	a1,s3		// 10ec
    move	a0,s1		// 10f0
    jal	func_f64_c		// 10f4
    move	a1,s0		// 10f8
    move	a2,s1		// 10fc
    move	a0,s2		// 1100
    jal	xor_64_bytes		// 1104
    move	a1,s2		// 1108
    move	a0,s1		// 110c
    jal	copy_32_bytes		// 1110
    move	a1,s5		// 1114
    move	a0,s1		// 1118
    jal	func_f64_c		// 111c
    move	a1,s0		// 1120
    move	a0,s4		// 1124
    move	a1,s4		// 1128
    jal	xor_64_bytes		// 112c
    move	a2,s1		// 1130
    move	a0,s2		// 1134

	__1138:
    jal	func_dd8_c		// 1138
    li	a1,1		// 113c
    bnez	v0,__10c8		// 1140
    move	s0,v0		// 1144
    lw	ra,40(sp)		// 1148
    lw	s5,36(sp)		// 114c
    lw	s4,32(sp)		// 1150
    lw	s3,28(sp)		// 1154
    lw	s2,24(sp)		// 1158
    lw	s1,20(sp)		// 115c
    lw	s0,16(sp)		// 1160
    jr	ra		// 1164
    addiu	sp,sp,48		// 1168

	__116c:
    jal	func_f28_c      /* only called here and 4 lines down */		// 116c
    negu	s0,s0		// 1170
    move	a0,s4		// 1174
    jal	func_f28_c      /* only called here and 4 lines up */		// 1178
    move	a1,s5		// 117c
    b	__10e8		// 1180
    move	a0,s1		// 1184
.end func_1030_asm

.globl func_1188_asm
.ent func_1188_asm
func_1188_asm:
    addiu	sp,sp,-24		// 1188
    move	a1,zero		// 118c
    sw	s0,16(sp)		// 1190
    sw	ra,20(sp)		// 1194
    jal	func_dd8_c		// 1198
    move	s0,a0		// 119c
    addiu	a0,v0,31		// 11a0
    slti	v1,v0,0		// 11a4
    movn	v0,a0,v1		// 11a8
    sra	v0,v0,0x5		// 11ac
    addiu	a3,v0,1		// 11b0
    blez	a3,__11f8		// 11b4
    move	a2,zero		// 11b8
    move	a1,a3		// 11bc
    move	a0,s0		// 11c0

	__11c4:
    lw	t0,0(a0)		// 11c4
    addiu	a1,a1,-1		// 11c8
    sll	t2,t0,0x1		// 11cc
    or	t1,t2,a2		// 11d0
    sw	t1,0(a0)		// 11d4
    srl	a2,t0,0x1f		// 11d8
    bnez	a1,__11c4		// 11dc
    addiu	a0,a0,4		// 11e0
    beqz	a2,__11fc		// 11e4
    lw	ra,20(sp)		// 11e8
    sll	t3,a3,0x2		// 11ec
    addu	a1,t3,s0		// 11f0
    sw	a2,0(a1)		// 11f4

	__11f8:
    lw	ra,20(sp)		// 11f8

	__11fc:
    lw	s0,16(sp)		// 11fc
    jr	ra		// 1200
    addiu	sp,sp,24		// 1204
.end func_1188_asm

.globl func_1208_asm
.ent func_1208_asm
func_1208_asm:
    addiu	sp,sp,-40		// 1208
    move	a0,a1		// 120c
    sw	s2,24(sp)		// 1210
    move	s2,a1		// 1214
    move	a1,zero		// 1218
    sw	s3,28(sp)		// 121c
    sw	s0,16(sp)		// 1220
    move	s3,a2		// 1224
    sw	ra,32(sp)		// 1228
    jal	func_dd8_c		// 122c
    sw	s1,20(sp)		// 1230
    addiu	s0,v0,-233		// 1234
    move	a0,s2		// 1238
    jal	func_e58_c                /* only called from here */		// 123c
    move	a1,s3		// 1240
    bltz	s0,__129c		// 1244
    lui	v0,0xbfc3		// 1248
	la s1, __bss + 0x0c20
    move	a0,s1		// 1250

	__1254:
    jal	clear_memory		// 1254
    li	a1,16		// 1258
    move	a0,s1		// 125c
    jal	copy_32_bytes		// 1260
    move	a1,s3		// 1264
    move	a1,s0		// 1268
    jal	func_f64_c		// 126c
    move	a0,s1		// 1270
    move	a0,s2		// 1274
    move	a1,s2		// 1278
    jal	xor_64_bytes		// 127c
    move	a2,s1		// 1280
    move	a0,s2		// 1284
    jal	func_dd8_c		// 1288
    move	a1,zero		// 128c
    addiu	s0,v0,-233		// 1290
    bgez	s0,__1254		// 1294
    move	a0,s1		// 1298

	__129c:
    lw	ra,32(sp)		// 129c
    lw	s3,28(sp)		// 12a0
    lw	s2,24(sp)		// 12a4
    lw	s1,20(sp)		// 12a8
    lw	s0,16(sp)		// 12ac
    jr	ra		// 12b0
    addiu	sp,sp,40		// 12b4
.end func_1208_asm

func_12b8_asm:
    addiu	sp,sp,-40		// 12b8
    lui	v1,0xbfc3		// 12bc
    sw	s4,32(sp)		// 12c0
	la s4, __bss + 0x1220
    sw	s3,28(sp)		// 12c8
    sw	s0,16(sp)		// 12cc
    move	s3,a0		// 12d0
    move	s0,a1		// 12d4
    move	a0,s4		// 12d8
    li	a1,8		// 12dc
    sw	ra,36(sp)		// 12e0
    sw	s2,24(sp)		// 12e4
    sw	s1,20(sp)		// 12e8
    jal	clear_memory		// 12ec
    move	s1,a2		// 12f0
    lui	v0,0xbfc3		// 12f4
	la s2, __bss + 0x0420
    move	a0,s2		// 12fc
    jal	clear_memory		// 1300
    li	a1,16		// 1304
    move	a1,s0		// 1308
    jal	copy_32_bytes		// 130c
    move	a0,s4		// 1310
    move	a1,s1		// 1314
    jal	copy_32_bytes		// 1318
    move	a0,s2		// 131c
    li	s0,1		// 1320
    li	t3,8		// 1324
    move	s1,zero		// 1328
    slt	t2,zero,t3		// 132c

	__1330:
    move	t0,s4		// 1330
    li	a3,7		// 1334
    move	t1,zero		// 1338

	__133c:
    lw	a1,0(t0)		// 133c
    and	a0,a1,s0		// 1340
    beqzl	a0,__1384		// 1344
    addiu	a3,a3,-1		// 1348
    beqzl	t2,__1384		// 134c
    addiu	a3,a3,-1		// 1350
    move	a2,s2		// 1354
    addu	a0,t1,s3		// 1358
    move	a1,t3		// 135c

	__1360:
    lw	t5,0(a0)		// 1360
    lw	t6,0(a2)		// 1364
    addiu	a1,a1,-1		// 1368
    xor	t4,t5,t6		// 136c
    sw	t4,0(a0)		// 1370
    addiu	a2,a2,4		// 1374
    bnez	a1,__1360		// 1378
    addiu	a0,a0,4		// 137c
    addiu	a3,a3,-1		// 1380

	__1384:
    addiu	t0,t0,4		// 1384
    bgez	a3,__133c		// 1388
    addiu	t1,t1,4		// 138c
    li	a2,31		// 1390
    beql	s1,a2,__13cc		// 1394
    addiu	s1,s1,1		// 1398
    jal	func_1188_c        /* only called from here */		// 139c
    move	a0,s2		// 13a0
    move	a0,s2		// 13a4
    jal	func_dd8_c		// 13a8
    move	a1,zero		// 13ac
    addiu	t0,v0,31		// 13b0
    slti	t1,v0,0		// 13b4
    movn	v0,t0,t1		// 13b8
    sra	a3,v0,0x5		// 13bc
    sll	s0,s0,0x1		// 13c0
    addiu	t3,a3,1		// 13c4
    addiu	s1,s1,1		// 13c8

	__13cc:
    slti	t2,s1,32		// 13cc
    bnezl	t2,__1330		// 13d0
    slt	t2,zero,t3		// 13d4
    lw	ra,36(sp)		// 13d8
    lw	s4,32(sp)		// 13dc
    lw	s3,28(sp)		// 13e0
    lw	s2,24(sp)		// 13e4
    lw	s1,20(sp)		// 13e8
    lw	s0,16(sp)		// 13ec
    jr	ra		// 13f0
    addiu	sp,sp,40		// 13f4

func_13f8_asm:
    li	a3,7		// 13f8

	__13fc:
    lw	t0,0(a1)		// 13fc
    lw	v1,0(a2)		// 1400
    addiu	a3,a3,-1		// 1404
    xor	v0,t0,v1		// 1408
    sw	v0,0(a0)		// 140c
    addiu	a1,a1,4		// 1410
    addiu	a0,a0,4		// 1414
    bgez	a3,__13fc		// 1418
    addiu	a2,a2,4		// 141c
    jr	ra		// 1420
    nop		// 1424

.globl func_1428_asm
.ent func_1428_asm
func_1428_asm:
    move	t0,a0		// 1428
    lw	t1,4(a1)		// 142c
    move	a3,zero		// 1430
    lw	a2,0(a1)		// 1434

	__1438:
    addu	a1,t0,a3		// 1438
    lbu	v1,0(a2)		// 143c
    lbu	t2,0(a1)		// 1440
    addiu	a3,a3,1		// 1444
    xor	v0,t2,v1		// 1448
    slti	a0,a3,29		// 144c
    sb	v0,0(a1)		// 1450
    bnez	a0,__1438		// 1454
    addiu	a2,a2,1		// 1458
    move	a2,t1		// 145c
    li	a3,29		// 1460

	__1464:
    addu	t3,t0,a3		// 1464
    lbu	t6,0(a2)		// 1468
    lbu	t5,0(t3)		// 146c
    addiu	a3,a3,1		// 1470
    xor	t4,t5,t6		// 1474
    slti	t1,a3,32		// 1478
    sb	t4,0(t3)		// 147c
    bnez	t1,__1464		// 1480
    addiu	a2,a2,1		// 1484
    jr	ra		// 1488
    nop		// 148c
.end func_1428_asm

.globl func_1490_asm
.ent func_1490_asm
func_1490_asm:
    addiu	sp,sp,-56		// 1490
    sw	ra,48(sp)		// 1494
    sw	s7,44(sp)		// 1498
    sw	s6,40(sp)		// 149c
    sw	s5,36(sp)		// 14a0
    sw	s4,32(sp)		// 14a4
    sw	s3,28(sp)		// 14a8
    sw	s2,24(sp)		// 14ac
    sw	s1,20(sp)		// 14b0
    sw	s0,16(sp)		// 14b4
    move	s7,a0		// 14b8
    lw	a0,0(a2)		// 14bc
    move	s6,a2		// 14c0
    move	s5,a1		// 14c4
    jal	clear_memory		// 14c8
    li	a1,8		// 14cc
    lw	a0,4(s6)		// 14d0
    jal	clear_memory		// 14d4
    li	a1,8		// 14d8
    lui	t0,0xbfc3		// 14dc
	la s2, __bss + 0x0120
    move	a0,s2		// 14e4
    jal	clear_memory		// 14e8
    li	a1,16		// 14ec
    lui	a3,0xbfc3		// 14f0
	la s1, __bss + 0x0e20
    move	a0,s1		// 14f8
    jal	clear_memory		// 14fc
    li	a1,16		// 1500
    lui	a1,0xbfc3		// 1504
	la s3, __bss + 0x0520
    lw	a2,4(s5)		// 150c
    lw	a1,4(s7)		// 1510
    jal	func_13f8_c		// 1514
    move	a0,s3		// 1518
    lui	a0,0xbfc3		// 151c
	la s4, __bss + 0x0620
    lw	a2,0(s5)		// 1524
    lw	a1,0(s7)		// 1528
    jal	func_13f8_c		// 152c
    move	a0,s4		// 1530
    move	a0,s1		// 1534
    jal	func_1030_c    /* called in one other place */		// 1538
    move	a1,s4		// 153c
    lui	v1,0xbfc3		// 1540
	la s0, __bss + 0x0d20
    move	a0,s0		// 1548
    jal	clear_memory		// 154c
    li	a1,16		// 1550
    move	a0,s0		// 1554
    move	a1,s1		// 1558
    jal	func_12b8_c		// 155c
    move	a2,s3		// 1560
	la s5, _data_3400
    move	a0,s0		// 156c
    move	a1,s0		// 1570
    jal	func_1208_c		// 1574
    move	a2,s5		// 1578
    la	a2,_data_34c8 // 1580
    move	a0,s3		// 1584
    jal	func_13f8_c		// 1588
    move	a1,s0		// 158c
    move	a0,s2		// 1590
    jal	clear_memory		// 1594
    li	a1,16		// 1598
    move	a0,s2		// 159c
    move	a1,s0		// 15a0
    jal	func_12b8_c		// 15a4
    move	a2,s0		// 15a8
    move	a0,s2		// 15ac
    move	a1,s2		// 15b0
    jal	func_1208_c		// 15b4
    move	a2,s5		// 15b8
    move	a0,s1		// 15bc
    move	a1,s3		// 15c0
    jal	func_13f8_c		// 15c4
    move	a2,s2		// 15c8
    lw	a0,0(s6)		// 15cc
    move	a1,s1		// 15d0
    jal	func_13f8_c		// 15d4
    move	a2,s4		// 15d8
    lw	a1,0(s7)		// 15dc
    lw	a2,0(s6)		// 15e0
    jal	func_13f8_c		// 15e4
    move	a0,s3		// 15e8
    lw	a2,4(s7)		// 15ec
    lw	a1,0(s6)		// 15f0
    jal	func_13f8_c		// 15f4
    move	a0,s4		// 15f8
    move	a0,s1		// 15fc
    jal	clear_memory		// 1600
    li	a1,16		// 1604
    move	a0,s1		// 1608
    move	a1,s3		// 160c
    jal	func_12b8_c		// 1610
    move	a2,s0		// 1614
    move	a0,s1		// 1618
    move	a1,s1		// 161c
    jal	func_1208_c		// 1620
    move	a2,s5		// 1624
    lw	a0,4(s6)		// 1628
    move	a1,s1		// 162c
    move	a2,s4		// 1630
    lw	ra,48(sp)		// 1634
    lw	s7,44(sp)		// 1638
    lw	s6,40(sp)		// 163c
    lw	s5,36(sp)		// 1640
    lw	s4,32(sp)		// 1644
    lw	s3,28(sp)		// 1648
    lw	s2,24(sp)		// 164c
    lw	s1,20(sp)		// 1650
    lw	s0,16(sp)		// 1654
    j	func_13f8_c		// 1658
    addiu	sp,sp,56		// 165c
.end func_1490_asm

// suspect 2 args, return void
.global func_1660_asm
.ent func_1660_asm
func_1660_asm:
    addiu	sp,sp,-56		// 1660
    sw	ra,48(sp)		// 1664
    sw	s7,44(sp)		// 1668
    sw	s6,40(sp)		// 166c
    sw	s5,36(sp)		// 1670
    sw	s4,32(sp)		// 1674
    sw	s3,28(sp)		// 1678
    sw	s2,24(sp)		// 167c
    sw	s1,20(sp)		// 1680
    sw	s0,16(sp)		// 1684
    move	s7,a0		// 1688
    lw	a0,0(a1)		// 168c
    move	s6,a1		// 1690
    jal	clear_memory		// 1694
    li	a1,8		// 1698
    lw	a0,4(s6)		// 169c
    jal	clear_memory		// 16a0
    li	a1,8		// 16a4
    lui	t1,0xbfc3		// 16a8
    //addiu	s3,t1,-25544		// 16ac
	la s3, __bss + 0x0720
    move	a0,s3		// 16b0
    jal	clear_memory		// 16b4
    li	a1,16		// 16b8
    lui	t0,0xbfc3		// 16bc
    la	s4, __bss + 0x0fa0 // 16c0
    move	a0,s4		// 16c4
    jal	clear_memory		// 16c8
    li	a1,16		// 16cc
    lui	a3,0xbfc3		// 16d0
    la	s2, __bss + 0x0b20		// 16d4
    move	a0,s2		// 16d8
    jal	clear_memory		// 16dc
    li	a1,16		// 16e0
    lw	a1,0(s7)		// 16e4
    jal	func_1030_c    /* called in one other place */		// 16e8
    move	a0,s2		// 16ec
    lui	a1,0xbfc3		// 16f0
    la	s1, __bss + 0x09a0		// 16f4
    move	a0,s1		// 16f8
    jal	clear_memory		// 16fc
    li	a1,16		// 1700
    lw	a2,4(s7)		// 1704
    move	a0,s1		// 1708
    jal	func_12b8_c		// 170c
    move	a1,s2		// 1710
	la s5, _data_3400 /* g_crypt_key6 */
    move	a1,s1		// 171c
    move	a0,s1		// 1720
    jal	func_1208_c		// 1724
    move	a2,s5		// 1728
    lui	v1,0xbfc3		// 172c
	la s0, __bss + 0x0220
    lw	a1,0(s7)		// 1734
    move	a0,s0		// 1738
    jal	func_13f8_c		// 173c
    move	a2,s1		// 1740
	la a2, _data_34c8
    move	a0,s2		// 174c
    jal	func_13f8_c		// 1750
    move	a1,s0		// 1754
    move	a0,s3		// 1758
    jal	clear_memory		// 175c
    li	a1,16		// 1760
    move	a0,s3		// 1764
    move	a1,s0		// 1768
    jal	func_12b8_c		// 176c
    move	a2,s0		// 1770
    move	a0,s3		// 1774
    move	a1,s3		// 1778
    jal	func_1208_c		// 177c
    move	a2,s5		// 1780
    lw	a0,0(s6)		// 1784
    move	a2,s3		// 1788
    jal	func_13f8_c		// 178c
    move	a1,s2		// 1790
    move	a0,s1		// 1794
    jal	clear_memory		// 1798
    li	a1,16		// 179c
	la a2, _data_3460
    move	a1,s0		// 17a4
    move	a0,s2		// 17a8
    jal	func_13f8_c		// 17ac
	nop
    lw	a2,0(s6)		// 17b4
    move	a0,s1		// 17b8
    jal	func_12b8_c		// 17bc
    move	a1,s2		// 17c0
    move	a2,s5		// 17c4
    move	a0,s1		// 17c8
    jal	func_1208_c		// 17cc
    move	a1,s1		// 17d0
    move	a0,s4		// 17d4
    jal	clear_memory		// 17d8
    li	a1,16		// 17dc
    lw	a1,0(s7)		// 17e0
    move	a0,s4		// 17e4
    jal	func_12b8_c		// 17e8
    move	a2,a1		// 17ec
    move	a0,s4		// 17f0
    move	a1,s4		// 17f4
    jal	func_1208_c		// 17f8
    move	a2,s5		// 17fc
    lw	a0,4(s6)		// 1800
    move	a1,s1		// 1804
    move	a2,s4		// 1808
    lw	ra,48(sp)		// 180c
    lw	s7,44(sp)		// 1810
    lw	s6,40(sp)		// 1814
    lw	s5,36(sp)		// 1818
    lw	s4,32(sp)		// 181c
    lw	s3,28(sp)		// 1820
    lw	s2,24(sp)		// 1824
    lw	s1,20(sp)		// 1828
    lw	s0,16(sp)		// 182c
    j	func_13f8_c		// 1830
    addiu	sp,sp,56		// 1834
.end func_1660_asm

// returns an int, takes 3 args
// spills to stack a few times, but just words afaict
.globl func_1838_asm
.ent func_1838_asm
func_1838_asm:
    addiu	sp,sp,-56		// 1838
    sw	ra,48(sp)		// 183c
    sw	s5,44(sp)		// 1840
    sw	s4,40(sp)		// 1844
    sw	s3,36(sp)		// 1848
    sw	s2,32(sp)		// 184c
    sw	s1,28(sp)		// 1850
    sw	s0,24(sp)		// 1854
    lui	t4,0xbfc3		// 1858
    lui	t2,0xbfc3		// 185c
    move	s4,a0		// 1860
    lw	a0,0(a2)		// 1864
    move	s1,a2		// 1868
	la t3, __bss + 0x0820
	la t1, __bss + 0x0aa0
    move	s3,a1		// 1874
    li	a1,8		// 1878
    sw	t3,16(sp)		// 187c
    jal	clear_memory		// 1880
    sw	t1,20(sp)		// 1884
    lw	a0,4(s1)		// 1888
    jal	clear_memory		// 188c
    li	a1,8		// 1890
    lw	a0,16(sp)		// 1894
    jal	clear_memory		// 1898
    li	a1,8		// 189c
    lw	a0,20(sp)		// 18a0
    jal	clear_memory		// 18a4
    li	a1,8		// 18a8
    move	a0,s4		// 18ac
    jal	func_dd8_c		// 18b0
    li	a1,1		// 18b4
    slti	a1,v0,0		// 18b8
    addiu	a0,v0,31		// 18bc
    movz	a0,v0,a1		// 18c0
    move	a3,v0		// 18c4
    sra	v0,a0,0x5		// 18c8
    sll	t0,v0,0x2		// 18cc
    lw	a0,16(sp)		// 18d0
    lw	a1,0(s3)		// 18d4
    addu	a2,t0,s4		// 18d8
    sll	v1,v0,0x5		// 18dc
    subu	s0,a3,v1		// 18e0
    lw	s2,0(a2)		// 18e4
    jal	copy_32_bytes		// 18e8
    addiu	s5,v0,-1		// 18ec
    lw	a0,20(sp)		// 18f0
    lw	a1,4(s3)		// 18f4
    addiu	s0,s0,-1		// 18f8

	__18fc:
    jal	copy_32_bytes		// 18fc
    nop		// 1900

	__1904:
    bltz	s0,__196c		// 1904
    addiu	a0,sp,16		// 1908
    jal	func_1660_c    /* only called here and below */		// 190c
    move	a1,s1		// 1910
    lw	a0,16(sp)		// 1914
    jal	copy_32_bytes		// 1918
    lw	a1,0(s1)		// 191c
    lw	a0,20(sp)		// 1920
    jal	copy_32_bytes		// 1924
    lw	a1,4(s1)		// 1928
    li	t7,1		// 192c
    sllv	t6,t7,s0		// 1930
    and	t5,t6,s2		// 1934
    addiu	a0,sp,16		// 1938
    move	a1,s3		// 193c
    move	a2,s1		// 1940
    beqz	t5,__1904		// 1944
    addiu	s0,s0,-1		// 1948
    jal	func_1490_c   /* only called here and below */		// 194c
    nop		// 1950
    lw	a0,16(sp)		// 1954
    jal	copy_32_bytes		// 1958
    lw	a1,0(s1)		// 195c
    lw	a0,20(sp)		// 1960
    b	__18fc		// 1964
    lw	a1,4(s1)		// 1968

	__196c:
    bltz	s5,__1a04		// 196c
    sll	s2,s5,0x2		// 1970
    addu	s4,s2,s4		// 1974

	__1978:
    lw	s2,0(s4)		// 1978
    b	__198c		// 197c
    li	s0,31		// 1980

	__1984:
    bltzl	s0,__19fc		// 1984
    addiu	s5,s5,-1		// 1988

	__198c:
    addiu	a0,sp,16		// 198c

	__1990:
    jal	func_1660_c    /* only called here and above */		// 1990
    move	a1,s1		// 1994
    lw	a0,16(sp)		// 1998
    jal	copy_32_bytes		// 199c
    lw	a1,0(s1)		// 19a0
    lw	a0,20(sp)		// 19a4
    jal	copy_32_bytes		// 19a8
    lw	a1,4(s1)		// 19ac
    li	ra,1		// 19b0
    sllv	t9,ra,s0		// 19b4
    and	t8,t9,s2		// 19b8
    addiu	a0,sp,16		// 19bc
    move	a1,s3		// 19c0
    move	a2,s1		// 19c4
    beqz	t8,__1984		// 19c8
    addiu	s0,s0,-1		// 19cc
    jal	func_1490_c   /* only called here and above */		// 19d0
    nop		// 19d4
    lw	a0,16(sp)		// 19d8
    jal	copy_32_bytes		// 19dc
    lw	a1,0(s1)		// 19e0
    lw	a0,20(sp)		// 19e4
    jal	copy_32_bytes		// 19e8
    lw	a1,4(s1)		// 19ec
    bgez	s0,__1990		// 19f0
    addiu	a0,sp,16		// 19f4
    addiu	s5,s5,-1		// 19f8

	__19fc:
    bgez	s5,__1978		// 19fc
    addiu	s4,s4,-4		// 1a00

	__1a04:
    lw	a0,0(s1)		// 1a04
    jal	copy_32_bytes		// 1a08
    lw	a1,16(sp)		// 1a0c
    lw	a0,4(s1)		// 1a10
    jal	copy_32_bytes		// 1a14
    lw	a1,20(sp)		// 1a18
    lw	ra,48(sp)		// 1a1c
    lw	s5,44(sp)		// 1a20
    lw	s4,40(sp)		// 1a24
    lw	s3,36(sp)		// 1a28
    lw	s2,32(sp)		// 1a2c
    lw	s1,28(sp)		// 1a30
    lw	s0,24(sp)		// 1a34
    move	v0,zero		// 1a38
    jr	ra		// 1a3c
    addiu	sp,sp,56		// 1a40
.end func_1838_asm

.globl func_1a44_asm
.ent func_1a44_asm
func_1a44_asm:
    addiu	sp,sp,-24		// 1a44
    sw	ra,20(sp)		// 1a48
    sw	s0,16(sp)		// 1a4c
    lui	v0,0xbfc3		// 1a50
    move	s0,a0		// 1a54
    lw	a0,0(a0)		// 1a58
	la a1, _data_3440
    jal	copy_32_bytes		// 1a5c
	nop
    lw	a0,4(s0)		// 1a64
	la a1, _data_3420
    jal	copy_32_bytes		// 1a6c
	nop
    lw	ra,20(sp)		// 1a74
    lw	s0,16(sp)		// 1a78
    move	v0,zero		// 1a7c
    jr	ra		// 1a80
    addiu	sp,sp,24		// 1a84
.end func_1a44_asm

.globl func_1a88_asm
.ent func_1a88_asm
func_1a88_asm:
    lui	t0,0xbfc3		// 1a88
    addiu	sp,sp,-40		// 1a8c
	la v1, __bss + 0x0f20
    lui	a3,0xbfc3		// 1a94
	la v0, __bss + 0x11a0
    sw	s2,32(sp)		// 1a9c
    sw	s1,28(sp)		// 1aa0
    move	s2,a0		// 1aa4
    move	s1,a1		// 1aa8
    move	a0,v1		// 1aac
    li	a1,8		// 1ab0
    sw	ra,36(sp)		// 1ab4
    sw	v0,20(sp)		// 1ab8
    sw	v1,16(sp)		// 1abc
    sw	s0,24(sp)		// 1ac0
    jal	clear_memory		// 1ac4
    move	s0,a2		// 1ac8
    lw	a0,20(sp)		// 1acc
    jal	clear_memory		// 1ad0
    li	a1,8		// 1ad4
    move	a0,s0		// 1ad8
    move	a1,s1		// 1adc
    jal	func_1838_c    /* only called from here */		// 1ae0
    addiu	a2,sp,16		// 1ae4
    move	s0,v0		// 1ae8
    move	a0,s2		// 1aec
    bnez	v0,__1b00		// 1af0
    addiu	a1,sp,16		// 1af4
    jal	func_1428_c /* only called from here */		// 1af8
    nop		// 1afc

	__1b00:
    move	v0,s0		// 1b00
    lw	ra,36(sp)		// 1b04
    lw	s2,32(sp)		// 1b08
    lw	s1,28(sp)		// 1b0c
    lw	s0,24(sp)		// 1b10
    jr	ra		// 1b14
    addiu	sp,sp,40		// 1b18
.end func_1a88_asm

.globl func_1b1c
.ent func_1b1c
func_1b1c:
    addiu	sp,sp,-32		// 1b1c
    sw	s1,20(sp)		// 1b20
    lui	t0,0xbfc3		// 1b24
    move	s1,a1		// 1b28
    sw	ra,24(sp)		// 1b2c
    sw	s0,16(sp)		// 1b30
    move	a1,a0		// 1b34
    move	s0,a3		// 1b38
    move	a0,s1		// 1b3c
    seh	a2,a2		// 1b40
    addiu	v0,t0,_offset_libc		// 1b44
	jal    memcpy
    move	a3,zero		// 1b4c
    ext	a3,s0,0x4,0x4		// 1b50
    addiu	a2,a3,16		// 1b54
    addu	v1,a2,s1		// 1b58
    lbu	v0,0(v1)		// 1b5c
    andi	a1,s0,0xf		// 1b60
    addu	s0,a1,s1		// 1b64
    lbu	a0,0(s0)		// 1b68
    lw	ra,24(sp)		// 1b6c
    sb	v0,0(s0)		// 1b70
    lw	s1,20(sp)		// 1b74
    lw	s0,16(sp)		// 1b78
    addiu	sp,sp,32		// 1b7c
    jr	ra		// 1b80
    sb	a0,0(v1)		// 1b84
.end func_1b1c

.globl func_1b88_asm
.ent func_1b88_asm
func_1b88_asm:
	la      t4,_data_3484
    move	t5,a1		// 1b90
    move	t3,a0		// 1b94
    move	t1,zero		// 1b98
    move	t0,a1		// 1b9c
    move	t2,t4		// 1ba0
    move	a3,a2		// 1ba4

	__1ba8:
    addu	a0,t3,t1		// 1ba8
    lbu	t9,0(t2)		// 1bac
    lbu	t8,0(a0)		// 1bb0
    addiu	t1,t1,1		// 1bb4
    xor	t7,t8,t9		// 1bb8
    sb	t7,0(a3)		// 1bbc
    lbu	v1,0(t0)		// 1bc0
    slti	a1,t1,16		// 1bc4
    xor	t6,t7,v1		// 1bc8
    sb	t6,0(a0)		// 1bcc
    addiu	a3,a3,1		// 1bd0
    addiu	t2,t2,1		// 1bd4
    bnez	a1,__1ba8		// 1bd8
    addiu	t0,t0,1		// 1bdc
    addiu	a3,t5,16		// 1be0
    addiu	t1,t4,16		// 1be4
    addiu	a2,a2,16		// 1be8
    li	t0,16		// 1bec

	__1bf0:
    addu	t4,t3,t0		// 1bf0
    lbu	t6,0(t1)		// 1bf4
    lbu	a0,0(t4)		// 1bf8
    addiu	t0,t0,1		// 1bfc
    xor	v0,a0,t6		// 1c00
    sb	v0,0(a2)		// 1c04
    lbu	a1,-16(a3)		// 1c08
    slti	t2,t0,20		// 1c0c
    xor	t5,v0,a1		// 1c10
    sb	t5,0(t4)		// 1c14
    addiu	a2,a2,1		// 1c18
    addiu	t1,t1,1		// 1c1c
    bnez	t2,__1bf0		// 1c20
    addiu	a3,a3,1		// 1c24
    jr	ra		// 1c28
    nop		// 1c2c
.end func_1b88_asm

.globl func_1c30_asm
.ent func_1c30_asm
func_1c30_asm:
    addiu	sp,sp,-64		// 1c30
    sw	s1,52(sp)		// 1c34
    sw	s0,48(sp)		// 1c38
    move	s1,a0		// 1c3c
    move	s0,a2		// 1c40
    addu	a0,a0,a2		// 1c44
    addiu	a2,sp,24		// 1c48
    sw	ra,60(sp)		// 1c4c
    sw	s2,56(sp)		// 1c50
    sw	zero,24(sp)		// 1c54
    move	s2,a3		// 1c58
    sw	zero,28(sp)		// 1c5c
    sw	zero,32(sp)		// 1c60
    sw	zero,36(sp)		// 1c64
    jal	func_1b88_c      /* only called from here */		// 1c68
    sw	zero,40(sp)		// 1c6c
    move	a2,s1		// 1c70
    move	a3,s0		// 1c74
    addiu	a0,sp,24		// 1c78
    li	a1,20		// 1c7c
    jal	func_d78_c      /* only called from here. nb is effectively func_d2c */		// 1c80
    sw	s2,16(sp)		// 1c84
    lw	ra,60(sp)		// 1c88
    lw	s2,56(sp)		// 1c8c
    lw	s1,52(sp)		// 1c90
    lw	s0,48(sp)		// 1c94
    jr	ra		// 1c98
    addiu	sp,sp,64		// 1c9c
.end func_1c30_asm

// 5 arguments, one on the stack as 64(sp). returns a value.
.globl func_1ca0_asm
.ent func_1ca0_asm
func_1ca0_asm:
    addiu	sp,sp,-48		// 1ca0
    sw	s1,28(sp)		// 1ca4
    move	s1,a0		// 1ca8
    move	a0,a1		// 1cac
    lw	a1,64(sp)		// 1cb0
    sw	s0,24(sp)		// 1cb4
    addiu	s0,s1,3		// 1cb8
    li	v1,489		// 1cbc
    sw	s4,40(sp)		// 1cc0
    sw	s3,36(sp)		// 1cc4
    addiu	a1,a1,4		// 1cc8
    move	s3,a3		// 1ccc
    move	s4,a2		// 1cd0
    move	a3,a0		// 1cd4
    li	a2,489		// 1cd8
    move	a0,s0		// 1cdc
    sh	v1,16(sp)		// 1ce0
    sw	ra,44(sp)		// 1ce4
    jal	func_1c30_c               /* only called from here */		// 1ce8
    sw	s2,32(sp)		// 1cec
    lui	v0,0xbfc3		// 1cf0
    move	a0,s0		// 1cf4
    addiu	a1,sp,16		// 1cf8
    li	a2,2		// 1cfc
    addiu	s2,v0,_offset_libc		// 1d00
    li	a3,2		// 1d04
    li	s0,1		// 1d08
    jal	memcmp              // 1d0c
    sh	s0,16(sp)		// 1d10
    move	a0,s1		// 1d14
    addiu	a1,s1,492		// 1d18
    li	a2,492		// 1d1c
    bnez	v0,__1d90		// 1d20
    li	v1,24		// 1d24
    li	a3,492		// 1d28
    jal	func_abc_c		// 1d2c
    sh	a3,16(sp)		// 1d30
    addiu	a0,sp,16		// 1d34
    addiu	a1,s1,13		// 1d38
    li	a2,2		// 1d3c
    move	a3,zero		// 1d40
    bnez	v0,__1d90		// 1d44
    li	v1,2		// 1d48
    jal memcpy				// 1d4c
    sb	s0,0(s4)		// 1d50
    lhu	t1,16(sp)		// 1d54
    lw	a0,24(s3)		// 1d58
    addiu	t0,t1,16		// 1d5c
    move	a1,zero		// 1d60
    li	a2,32		// 1d64
    li	a3,1		// 1d68
    jal	memset		// 1d6c
    sh	t0,16(sp)		// 1d70
    lh	a2,16(sp)		// 1d74
    lw	a0,24(s3)		// 1d78
    addu	a1,a2,s1		// 1d7c
    move	a3,zero		// 1d80
    jal	memcpy			// 1d84
    li	a2,30		// 1d88
    move	v1,zero		// 1d8c

	__1d90:
    lw	ra,44(sp)		// 1d90
    lw	s4,40(sp)		// 1d94
    lw	s3,36(sp)		// 1d98
    lw	s2,32(sp)		// 1d9c
    lw	s1,28(sp)		// 1da0
    lw	s0,24(sp)		// 1da4
    move	v0,v1		// 1da8
    jr	ra		// 1dac
    addiu	sp,sp,48		// 1db0
.end func_1ca0_asm

// finished

.globl func_1db4_asm
.ent func_1db4_asm
func_1db4_asm:
	/* a0: file length
	 * a1: pInOutBuffer
	 * a2: *num_sectors_1
	 * a3: *num_sectors_2
	 * on the stack: several pointers to zeroed memory (in initUseBuffer), as far as I can tell

	 This function extracts something from pInOutBuffer which represents some number of sectors (twice)
	 and returns them by writing to their addresses. Returns 0 on success.

	 It presumably also does something to pInOutBuffer because the init buffer
	 is later filled with data.
	*/

    addiu	sp,sp,-744
    sw	s4,720(sp)
    lw	s4,776(sp)
    lui	a0,0xbfc3
    addiu	t6,s4,1536
    addiu	t5,s4,1664 // + 128
    addiu	t0,s4,1792 // + 128
    addiu	t1,s4,1920 // + 128
    addiu	t2,s4,2048 // + 128
    addiu	t3,s4,2176 // + 128
    addiu	t4,s4,2304 // + 128
    sw	s7,732(sp)
    sw	s5,724(sp)
    sw	s3,716(sp)
    addiu	s5,a0,_offset_libc
    sw	s1,708(sp)
    sw	s0,704(sp)
    move	s3,a1
    move	a0,s4
    move	a1,zero
    move	s1,a2
    move	s7,a3
    li	a2,512
    li	a3,1
    addiu	s0,s4,512
    sw	ra,740(sp)
    sw	t6,256(sp)
    sw	t5,260(sp)
    sw	t0,640(sp)
    sw	t1,124(sp)
    sw	t2,128(sp)
    sw	t3,680(sp)
    sw	t4,684(sp)
    sw	s8,736(sp)
    sw	s6,728(sp)
    sw	s2,712(sp)
    sh	zero,24(sp)
    sb	zero,672(sp)
    sb	zero,673(sp)
	jal  memset 
    lw	s8,772(sp)
    move	a0,s0
    move	a1,zero
    li	a2,512
    jal memset 
    li	a3,1

    //lui	v1,0xbfc3		// safe

	la s6, _firmware_signature_3498				// TODO check this actually works

	/* 1e74 */
    move	a0,s3
    move	a1,s6
    li	a2,16
	jal memcmp /* 1e80:	09f8a002 	*/
    li	a3,2
    seb	v0,v0
    bnez	v0,__1fa4
    li	v1,3
    lbu	t9,494(s3)
    move	a0,s0
    andi	a2,t9,0xf
    sb	a2,0(s1)
    lbu	t8,510(s3)
    li	a2,1024
    andi	a3,t8,0xf
    sb	a3,0(s7)
    lb	s2,0(s1)
    move	a3,zero
    sll	t7,s2,0x9
    addu	a1,t7,s3
    addiu	a1,a1,1024
    jal memcpy /*1ec8:	09f8a002 	memcpy */
    addiu	s2,sp,320

	/* 1ed0 */

    move	a0,s0		// 1ed0
    addiu	a1,sp,248		// 1ed4
    move	a2,s2		// 1ed8
    jal	func_808_c              /* only called from here */		// 1edc
    addiu	a3,sp,672		// 1ee0
    bnez	v0,__1fa0		// 1ee4
    move	s0,v0		// 1ee8
    lb	ra,0(s1)		// 1eec
    lb	v0,0(s7)		// 1ef0
    move	a0,s4		// 1ef4
    addu	s7,ra,v0		// 1ef8
    sll	s1,s7,0x9		// 1efc
    addu	s0,s1,s3		// 1f00
    addiu	a1,s0,2560		// 1f04
    li	a2,512		// 1f08
    jal memcpy //		// 1f0c
    move	a3,zero		// 1f10

    move	a0,s4		// 1f14
    move	a1,s8		// 1f18
    addiu	a2,sp,673		// 1f1c
    addiu	a3,sp,616		// 1f20
    jal	func_1ca0_c           /* only called from here */		// 1f24
    sw	s2,16(sp)		// 1f28
    bnez	v0,__1fa0		// 1f2c
    move	s0,v0		// 1f30
    addiu	s2,sp,32		// 1f34
    move	a0,s2		// 1f38
    move	a1,zero		// 1f3c
    li	a2,91		// 1f40
    jal memset 		//		// 1f44
    li	a3,1		// 1f48
    move	a0,s2		// 1f4c
    move	a1,s3		// 1f50
    li	a2,42		// 1f54
    jal memcpy		// 		// 1f58
    move	a3,zero		// 1f5c
    move	a1,s6		// 1f60
    move	a0,s2		// 1f64
    li	a2,16		// 1f68
    jal memcmp 		// 1f6c
    li	a3,2		// 1f70
    seb	s6,v0		// 1f74
    bnez	s6,__1fa0		// 1f78
    li	s0,3		// 1f7c
    lb	v1,56(sp)		// 1f80
    li	t4,126		// 1f84
    bne	v1,t4,__1fa0		// 1f88
    li	s0,8		// 1f8c
    lw	t2,52(sp)		// 1f90
    li	t3,512		// 1f94
    beq	t2,t3,__1fd8		// 1f98
    li	s0,3		// 1f9c

	__1fa0:
    move	v1,s0		// 1fa0

	__1fa4:
    lw	ra,740(sp)		// 1fa4
    lw	s8,736(sp)		// 1fa8
    lw	s7,732(sp)		// 1fac
    lw	s6,728(sp)		// 1fb0
    lw	s5,724(sp)		// 1fb4
    lw	s4,720(sp)		// 1fb8
    lw	s3,716(sp)		// 1fbc
    lw	s2,712(sp)		// 1fc0
    lw	s1,708(sp)		// 1fc4
    lw	s0,704(sp)		// 1fc8
    move	v0,v1		// 1fcc
    jr	ra		// 1fd0
    addiu	sp,sp,744		// 1fd4

	__1fd8:
    lbu	t0,57(sp)		// 1fd8
    li	t1,225		// 1fdc
    bne	t0,t1,__1fa4		// 1fe0
    move	v1,s0		// 1fe4
	la a1, _signature_34b0
    addiu	a0,sp,58		// 1ff0
    li	a2,16		// 1ff4
    jal memcmp // 1ff8
    li	a3,2		// 1ffc
    seb	t5,v0		// 2000
    bnez	t5,__1fa4		// 2004
    move	v1,s0		// 2008
    addiu	s6,s3,42		// 200c
    addiu	a0,sp,74		// 2010
    move	a1,s6		// 2014
    li	a2,49		// 2018
    jal memcpy		// 201c
    move	a3,zero		// 2020
    lb	a1,90(sp)		// 2024
    li	a0,3		// 2028
    bne	a1,a0,__1fa0		// 202c
    li	s0,5		// 2030
    lw	a0,124(sp)		// 2034
    move	a1,zero		// 2038
    li	a2,32		// 203c
    jal memset // 2040
    li	a3,1		// 2044
    lw	a0,128(sp)		// 2048
    move	a1,zero		// 204c
    li	a2,32		// 2050
    jal memset // 2054
    li	a3,1		// 2058
    lw	a0,124(sp)		// 205c
    addiu	a1,s3,91		// 2060
    li	a2,30		// 2064
    jal memcpy		// 2068
    move	a3,zero		// 206c
    lw	a0,128(sp)		// 2070
    addiu	a1,s3,121		// 2074
    li	a2,30		// 2078
    jal memcpy		// 207c
    move	a3,zero		// 2080
    lb	a1,252(sp)		// 2084
    jal	func_1a44_c        /* only called from here. Copies static data */		// 2088
    addiu	a0,sp,680		// 208c
    bnez	v0,__1fa0		// 2090
    move	s0,v0		// 2094
    addiu	s1,sp,91		// 2098
    lw	a2,640(sp)		// 209c
    move	a0,s1		// 20a0
    jal	func_1a88_c       /* only called from here */		// 20a4
    addiu	a1,sp,124		// 20a8
    bnez	v0,__1fa0		// 20ac
    move	s0,v0		// 20b0
    lw	a0,764(sp)		// 20b4
    move	a1,s1		// 20b8
    li	a2,32		// 20bc
    jal memcpy // 20c0
    move	a3,zero		// 20c4
    addiu	s0,s3,151		// 20c8
    lw	a0,764(sp)		// 20cc
    move	a2,s0		// 20d0
    move	a1,zero		// 20d4
    li	a3,361		// 20d8
    addiu	s1,sp,132		// 20dc
    jal	func_d80_c      /* only called from here */		// 20e0
    sw	s8,16(sp)		// 20e4
    move	a1,s0		// 20e8
    move	a0,s1		// 20ec
    li	a2,2		// 20f0
    jal memcpy		// 20f4
    move	a3,zero		// 20f8
    li	a2,2		// 20fc
    move	a1,s1		// 2100
    addiu	a0,sp,24		// 2104
    jal memcpy		// 2108
    move	a3,zero		// 210c
    lh	a2,24(sp)		// 2110
    li	t7,251		// 2114
    addiu	t8,a2,153		// 2118
    li	s0,3		// 211c
    bne	a2,t7,__1fa0		// 2120
    seh	v1,t8		// 2124
    addu	a1,v1,s3		// 2128
    addiu	a0,sp,140		// 212c
    li	a2,108		// 2130
    jal memcpy		// 2134
    move	a3,zero		// 2138
    lb	t9,140(sp)		// 213c
    li	s3,2		// 2140
    bne	t9,s3,__1fa0		// 2144
    li	s0,4		// 2148
    la a1, _signature_34ac // 2150
    addiu	a0,sp,141		// 2154
    li	a2,4		// 2158
    jal	memcmp		// 215c
    li	a3,2		// 2160
    seb	s7,v0		// 2164
    bnez	s7,__1fa0		// 2168
    li	s0,3		// 216c
    la	a1, _signature_34a8		// 2174
    addiu	a0,sp,145		// 2178
    li	a2,4		// 217c
    jal memcmp		// 2180
    li	a3,2		// 2184
    seb	v0,v0		// 2188
    bnez	v0,__1fa0		// 218c
    lb	v1,181(sp)		// 2190
    li	t4,-66		// 2194
    bne	v1,t4,__1fa0		// 2198
    li	s0,5		// 219c
    lw	a0,768(sp)		// 21a0
    move	a1,zero		// 21a4
    li	a2,512		// 21a8
    jal	memset		// 21ac
    li	a3,1		// 21b0
    lw	t1,768(sp)		// 21b4
    addiu	s7,sp,182		// 21b8
    addiu	s3,t1,492		// 21bc
    move	a3,zero		// 21c0
    addiu	a0,s4,476		// 21c4
    move	a1,s7		// 21c8
    jal	memcpy		// 21cc
    li	a2,16		// 21d0
    move	a0,s4		// 21d4
    li	a1,492		// 21d8
    jal	func_97c_c		// 21dc
    move	a2,s3		// 21e0
    lw	t2,768(sp)		// 21e4
    move	a1,s4		// 21e8
    lbu	s0,500(t2)		// 21ec
    move	a0,t2		// 21f0
    addu	s1,s0,t2		// 21f4
    move	a2,s0		// 21f8
    jal	memcpy  // 21fc
    move	a3,zero		// 2200
    move	a1,s7		// 2204
    move	a0,s1		// 2208
    li	a2,16		// 220c
    jal	memcpy		// 2210
    move	a3,zero		// 2214
    li	t3,476		// 2218
    subu	a2,t3,s0		// 221c
    addu	a1,s0,s4		// 2220
    addiu	a0,s1,16		// 2224
    jal	memcpy		// 2228
    move	a3,zero		// 222c
    lw	a2,768(sp)		// 2230
    move	a0,s3		// 2234
    li	a1,16		// 2238
    li	a3,492		// 223c
    jal	func_d2c_c		// 2240
    sw	s8,16(sp)		// 2244
    move	a0,s6		// 2248
    addiu	a1,sp,228		// 224c
    jal	func_abc_c		// 2250
    li	a2,450		// 2254
    bnez	v0,__1fa0		// 2258
    li	s0,2		// 225c
    addiu	a0,sp,324		// 2260
    addiu	a1,sp,149		// 2264
    li	a2,16		// 2268
    jal memcmp	// 226c
    li	a3,2		// 2270
    seb	s0,v0		// 2274
    beqz	s0,__2288		// 2278
    lw	a0,760(sp)		// 227c
    b	__1fa0		// 2280
    li	s0,1		// 2284

	__2288:
    addiu	a1,sp,688		// 2288
    li	a2,16		// 228c
    li	a3,2		// 2290
    sw	zero,688(sp)		// 2294
    sw	zero,692(sp)		// 2298
    sw	zero,696(sp)		// 229c
    jal	memcmp		// 22a0
    sw	zero,700(sp)		// 22a4
    beqz	v0,__1fa4		// 22a8
    move	v1,s0		// 22ac
    lw	a0,760(sp)		// 22b0
    addiu	a1,sp,165		// 22b4
    li	a2,16		// 22b8
    jal	memcmp		// 22bc
    li	a3,2		// 22c0
    seb	s4,v0		// 22c4
    li	s0,10		// 22c8
    b	__1fa0		// 22cc
    movz	s0,s4,s4		// 22d0
.end func_1db4_asm

.globl func_fw_decrypt_init
.ent func_fw_decrypt_init
func_fw_decrypt_init:
	/* 22d4 */
    addiu   sp,sp,-96
    sw  s0,56(sp)
    sw  ra,92(sp)
    sw  s8,88(sp)
    sw  s7,84(sp)
    sw  s6,80(sp)
    sw  s5,76(sp)
    sw  s4,72(sp)
    sw  s3,68(sp)
    sw  s2,64(sp)
    sw  s1,60(sp)

	/* 2300 */
    move    s0,a0
    addiu	a1,a0,4			// a1 = inOutLen
    lw	v1,4(a0)            /* = decrypt.inOutLen */
    lw	s6,0(a0)            /* = pInOutBuffer */
    lw	a0,8(a0)            /* = fileLength */
    li	v0,18432            /* decrypt.InOutLen should be 18432 bytes */
    sw	a1,44(sp)
    sw	a0,48(sp)
    lw	s7,12(s0)
    lw	s3,16(s0)
    lw	a0,20(s0)

	/* 232c */
    bne	v1,v0, __24dc_exit  /* decrypt.InOutLen wrong value? */
    li	a1,48
    li	a2,19888            /* decrypt.initusebufferlen */
    bne	a0,a2, __24dc_exit  /* decrypt.initusebufferlen wrong value? */
    lui	t3,0xbfc3
    addiu	s5,t3, _offset_libc
    move	a0,s3
    move	a1,zero
    li	a2,19888           /* decrypt.initusebufferlen */
    jal	memset             /* memset() to zero initusebuffer*/
    li	a3,1
	
	/* 2358 */
    lw	a0,48(sp)          /* fileLength*/
    addiu	t2,s3,32		// initusebuffer + 32
    addiu	t1,s3,48		// initusebuffer + 48
    addiu	t0,s3,17456     // initusebuffer + 17456
    move	a1,s6			// pInOutBuffer
    addiu	a3,sp,41		// ptr to unknown byte
    addiu	a2,sp,40		// ptr to unknown byte
    sw	t2,16(sp)			// initusebuffer + 32
    sw	t1,24(sp)			// initusebuffer + 48
    sw	t0,32(sp)			// initusebuffer + 17458
    sw	s3,20(sp)			// initusebuffer
    jal	func_1db4_c        /* only called from here: init? Uses 744 bytes of stack */
    sw	s7,28(sp)			// pGLBuffer
    addiu	a3,s3,16944  /* initusebuffer + 16944 */
    addiu	s4,s3,560    /* initusebuffer + 560 */
    sw	a3,52(sp)		/* initusebuffer + 16944 */
    bnez	v0,__24dc_exit
    move	a1,v0

	/* 23a0 */
    lw	t5,4(s0)		// inOutLen 		// 23a0
    li	t4,16384 		// 23a4
    addiu	s8,t5,-2048   // s8 = inOutLen - 2048		// 23a8
    bne	s8,t4,__24dc_exit		// 23ac
    li	a1,48		// 23b0

    move	a0,s4		// 23b4
    move	a1,zero		// 23b8
    li	a2,16384		// 23bc
	jal memset
    li	a3,1		// 23c4

    lb	t0,40(sp)		// byte_sp40 from func_1db4		// 23c8
    addiu	s0,s6,512	// pInOutBuffer + 512		// 23cc
    sll	a3,t0,0x9		// a3 = t0 << 9		// 23d0
    addiu	s1,a3,512   // s1 = (t0 << 9) + 512		// 23d4
    move	a1,s0		// 23d8
    move	a2,s1		// 23dc
    move	a0,s4		// 23e0
    jal		memcpy
    move	a3,zero		// 23e8

    lb	a2,41(sp)		// 23ec
    addu	a0,s0,s1    // a0 = (pInOutBuffer + 512) + (40(sp) << 9 + 512)		// 23f0
    sll	a1,a2,0x9				// 23f4
    addiu	s0,a1,512   // s0 = (41(sp) << 9) + 512		// 23f8
    addiu	s2,a0,1024  // s2 = (pInOutBuffer + 512 + (40(sp) << 9 + 512)) + 1024		// 23fc
    addu	s1,s4,s1	// s1 = initusebuffer + 560 + (40(sp) << 9 + 512)		// 2400
    move	a1,s2		// src = s2		// 2404
    move	a2,s0		// length = s0		// 2408
    move	a0,s1		// dest = s1		// 240c
    jal		memcpy
    move	a3,zero		// 2414

    lb	v1,40(sp)		// 2418
    lb	v0,41(sp)		// 241c
    addu	s2,s2,s0   // previous pInOutBuffer address += (41(sp) << 9) + 512		// 2420
    addu	ra,v1,v0   // ra = 40(sp) + 41(sp)		// 2424
    sll	t9,ra,0x9      // t9 = combined sector lengths in bytes		// 2428
    negu	t8,t9      // t8 =-t9		// 242c
    addu	a0,s1,s0   // a0 = previous initusebuffer end + (40(sp) << 9) + 512 (dst)		// 2430
    addiu	a1,s2,512     // add another sector buffer (src)		// 2434
    addiu	a2,t8,15360   // length: our negative sector length plus 30 sectors		// 2438
    jal		memcpy
    move	a3,zero		// 2440
    lw	s0,48(sp)			// s0 = fileLength		// 2444
    li	t6,16				// t6=16		// 2448
    sra	t7,s0,0x19			// t7 = fileLength >> 0x19 (=number of 512K chunks minus 1)		// 244c
    subu	v0,t6,t7		// v0 = 16 - t7, i.e. is file length under 8MB		// 2450
    blezl	v0,__245c		// if it's 8MB or over, branch and execute delay slot		// 2454
    li	v0,1				// this is only executed if branch taken.		// 2458

	__245c:
    move	s0,s4			// s0 = initusebuffer + 560		// 245c
    li	s1,16384			// s1 = 16384		// 2460
    b	__247c		// 2464
    sh	v0,42(sp)			// 42(sp) = 16 - (fileLength >> 0x19)		// 2468

	__246c:
    lh	a2,42(sp)			// body of a while loop while s1 >= 512.		// 246c
    jal	func_268c_c			// todo (this does some crypto).		// 2470
    addiu	s1,s1,-512		// trim a sector off s1		// 2474
    addiu	s0,s0,512		// add a sector to s0		// 2478

	__247c:
    slti	t1,s1,512		// t1 = (s1 < 512)?		// 247c
    move	a0,s0			// a0 = initusebuffer + 560		// 2480
    beqz	t1,__246c		// !(s1 < 512)? branch (taken)		// 2484
    move	a1,s3			// a1 = initusebuffer		// 2488
    bnez	s1,__2510		// s1 != 0? branch. (It's 16384, so we do)		// 248c
    lw	a0,52(sp)			// a0 = initusebuffer + 16944		// 2490
    move	a0,s6			// a0 = pInOutBuffer 	// 2494

	// note we come here from 2544, where a0 is also set to s6. (Why the duplication?)
	__2498:
    move	a1,s4			// a1 = initusebuffer+560		// 2498
    move	a2,s8			// a2 = inOutLen - 2048		// 249c
    jal		memcpy
    move	a3,zero		// 24a4
    addiu	a0,s7,260		// a0 = pGLBuffer + 260		// 24a8
    addiu	a1,sp,42		// src: 16 - (fileLength >> 0x19)		// 24ac
    li	a2,2				// length 2, so copy the halfword only		// 24b0
    jal		memcpy
    move	a3,zero					// 24b8
    move	a1,s3			// a1 = initusebuffer (src)		// 24bc
    addiu	a0,s7,264		// a0 = pGLBuffer + 264		// 24c0
    li	a2,32				// length 32 bytes		// 24c4
    jal		memcpy
    move	a3,zero		// 24cc
	lw	s3,44(sp)			// s3 = address of pInOutLen		// 24d0
    move	a1,zero			// return code		// 24d4
    sw	s8,0(s3)			// s8 = pInOutLen		// 24d8

__24dc_exit:
    lw  ra,92(sp)
    lw  s8,88(sp)
    lw  s7,84(sp)
    lw  s6,80(sp)
    lw  s5,76(sp)
    lw  s4,72(sp)
    lw  s3,68(sp)
    lw  s2,64(sp)
    lw  s1,60(sp)
    lw  s0,56(sp)
    move    v0,a1
    jr  ra
    addiu   sp,sp,96

	__2510:
	// coming from 248c
	// by this stage (thanks to the while loop), s1 is always < 512.
	// this does the final sector's worth of key derivation.
    move	a1,s0			// a1 = initusebuffer + 560		// 2510
    move	a2,s1			// a2 < 512		// 2514
    jal		memcpy // memcpy (a0 = initusebuffer + 16944)		// 2518
    move	a3,zero		// 251c
    lw	a0,52(sp)			// a0 = initusebuffer + 16944		// 2520
    lh	a2,42(sp)			// a2 = 16 - (fileLength >> 0x19)		// 2524
    jal	func_268c_c			// this does some crypto		// 2528
    move	a1,s3			// a1 = initusebuffer (as input to func_268c)		// 252c
    lw	a1,52(sp)			// a1 = initusebuffer + 16944		// 2530
    move	a0,s0			// a0 = initusebuffer + 560		// 2534
    move	a2,s1			// a2 < 512		// 2538
    jal		memcpy				// memcpy		// 253c
    move	a3,zero		// 2540
    b	__2498		// 2544
    move	a0,s6		// 2548
	// end of function

.end func_fw_decrypt_init

/* TODO this was automatically generated and thus(?) suspect */
.globl func_fw_decrypt_run_asm
.ent func_fw_decrypt_run_asm
func_fw_decrypt_run_asm:
    addiu sp,sp,-56                // 254c 
    lui a3,0xbfc3                  // 2550 
    lui v1,0xbfc3                  // 2554 
    sw s3,36(sp)                   // 2558 
    lui v0,0xbfc3                  // 255c 
    la s3,__bss + 0x1520           // 2560 addiu rewrite
    sw ra,48(sp)                   // 2564 
    sw s5,44(sp)                   // 2568 
    sw s4,40(sp)                   // 256c 
    sw s2,32(sp)                   // 2570 
    nop                            // 2574 addiu rewrite
    sw s1,28(sp)                   // 2578 
    sw s0,24(sp)                   // 257c 
    la s5,__bss + 0x1320           // 2580 addiu rewrite
    move s0,a2                     // 2584 
    move s1,a0                     // 2588 
    move s2,a1                     // 258c 
    move a0,s3                     // 2590 
    move a1,zero                   // 2594 
    li a2,32                       // 2598 
    jal memset                     // 259c 
    li a3,1                        // 25a0 
    move a0,s5                     // 25a4 
    move a1,zero                   // 25a8 
    li a2,512                      // 25ac 
    jal memset                     // 25b0 
    li a3,1                        // 25b4 
    addiu a0,sp,16                 // 25b8 
    addiu a1,s0,260                // 25bc 
    li a2,2                        // 25c0 
    jal memcpy                     // 25c4 
    move a3,zero                   // 25c8 
    move a0,s3                     // 25cc 
    addiu a1,s0,264                // 25d0 
    li a2,32                       // 25d4 
    jal memcpy                     // 25d8 
    move a3,zero                   // 25dc 
    b __25fc                       // 25e0 
    slti a2,s2,512                 // 25e4 

    __25e8:
    lh a2,16(sp)                   // 25e8 
    jal func_268c_c                  // 25ec 
    addiu s2,s2,-512               // 25f0 
    addiu s1,s1,512                // 25f4 
    slti a2,s2,512                 // 25f8 

    __25fc:
    move a0,s1                     // 25fc 
    beqz a2,__25e8                 // 2600 
    move a1,s3                     // 2604 
    bnez s2,__2630                 // 2608 
    lw ra,48(sp)                   // 260c 
    lw s5,44(sp)                   // 2610 
    lw s4,40(sp)                   // 2614 
    lw s3,36(sp)                   // 2618 
    lw s2,32(sp)                   // 261c 
    lw s1,28(sp)                   // 2620 
    lw s0,24(sp)                   // 2624 
    jr ra                          // 2628 
    addiu sp,sp,56                 // 262c 

    __2630:
    move a0,s5                     // 2630 
    move a1,s1                     // 2634 
    move a2,s2                     // 2638 
    jal memcpy                     // 263c 
    move a3,zero                   // 2640 
    lh a2,16(sp)                   // 2644 
    move a0,s5                     // 2648 
    jal func_268c_c                  // 264c 
    move a1,s3                     // 2650 
    move a0,s1                     // 2654 
    move a1,s5                     // 2658 
    move a2,s2                     // 265c 
    jal memcpy                     // 2660 
    move a3,zero                   // 2664 
    lw ra,48(sp)                   // 2668 
    lw s5,44(sp)                   // 266c 
    lw s4,40(sp)                   // 2670 
    lw s3,36(sp)                   // 2674 
    lw s2,32(sp)                   // 2678 
    lw s1,28(sp)                   // 267c 
    lw s0,24(sp)                   // 2680 
    jr ra                          // 2684 
    addiu sp,sp,56                 // 2688 

.end func_fw_decrypt_run_asm


.globl func_268c_asm
.ent func_268c_asm
func_268c_asm:
	// This now has a (horrific) C implementation
    addiu	sp,sp,-64		// 268c
    lui	t8,0xbfc3		// 2690
    sw	s6,56(sp)		// 2694
    sw	s4,48(sp)		// 2698
    sw	s5,52(sp)		// 269c
    sw	s3,44(sp)		// 26a0
    sw	s2,40(sp)		// 26a4
    sw	s1,36(sp)		// 26a8
    sw	s0,32(sp)		// 26ac
	la s6, _key_282c /* magic rodata key */		// 26b0
    lw	s5,28(a1)		// 26b4
    lw	v1,0(a1)		// 26b8
    lw	v0,4(a1)		// 26bc
    lw	t0,8(a1)		// 26c0
    lw	t1,12(a1)		// 26c4
    lw	t2,16(a1)		// 26c8
    lw	t3,20(a1)		// 26cc
    lw	t4,24(a1)		// 26d0
	la  s4, _key_282c
    lw	s3,28(s6)		// 26d8
    lw	t5,4(s6)		// 26dc
    lw	t6,8(s6)		// 26e0
    lw	t7,12(s6)		// 26e4
    lw	s0,16(s6)		// 26e8
    lw	s1,20(s6)		// 26ec
    lw	s2,24(s6)		// 26f0
    xor	a3,s4,v1		// 26f4 # key[0] ^ state[0]
    xor	t5,t5,v0		// 26f8
    xor	t6,t6,t0		// 26fc
    xor	t7,t7,t1		// 2700
    xor	s0,s0,t2		// 2704
    xor	s1,s1,t3		// 2708
    xor	s2,s2,t4		// 270c
    xor	s3,s3,s5		// 2710
    seh	s4,a2		// 2714
    sw	a3,0(sp)		// 2718
    move	s6,a0		// 271c
    sw	t5,4(sp)		// 2720
    sw	t6,8(sp)		// 2724
    sw	t7,12(sp)		// 2728
    sw	s0,16(sp)		// 272c
    sw	s1,20(sp)		// 2730
    sw	s2,24(sp)		// 2734
    sw	s3,28(sp)		// 2738
    blez	s4,__2808		// 273c
	//
    move	t8,zero		// 2740

	__2744:
    sll	v0,t8,0x13		// 2744
    sra	t9,v0,0xe		// 2748
    addu	v0,t9,s6 // v0 moves up in 32 byte chunks // 274c
    lw	t4,28(v0)    //t4 = data[offset + 7];		// 2750
    addiu	v1,t8,1		// offset += 1		// 2754
    lw	a0,0(v0)		// a0 = data[offset];		// 2758
    lw	a1,4(v0)		// 275c
    lw	a2,8(v0)		// 2760
    lw	a3,12(v0)		// 2764
    lw	t0,16(v0)		// 2768
    lw	t1,20(v0)		// 276c
    lw	t2,24(v0)		// 2770
    xor	t3,t5,s0	// t3 = scratch[1] ^ scratch[4]		// 2774
    seh	t8,v1		// 2778
    xor	a0,a0,t5	// a0 = data[offset] ^ scratch[1]		// 277c
    xor	v1,t4,t3	// v1 = data[offset + 7] ^ t3		// 2780
    xor	a1,a1,t6	// a1 = data[offset + 1] ^ scratch[2]		// 2784
    xor	a2,a2,t7	// a2 = data[offset + 2] ^ scratch[3]		// 2788
    xor	a3,a3,s0	// a3 = data[offset + 3] ^ scratch[4]		// 278c
    xor	t0,t0,s1	// t0 = data[offset + 4] ^ scratch[5]		// 2790
    xor	t1,t1,s2	// t1 = data[offset + 5] ^ scratch[6]		// 2794
    xor	t2,t2,s3	// t2 = data[offset + 6] ^ scratch[7]		// 2798
    xor	t4,t4,s5	// t4 = data[offset + 7] ^ rodatakey[7]		// 279c
    slt	t3,t8,s4	// t3 = offset < 16 - num_32mb_chunks_in_file (but at least 1) 27a0
    move	t9,t5	// unused: t9 = scratch[1]		// 27a4
    sw	v1,28(v0)	// data[offset + 7] ^= previous-scratch[1] ^ scratch[4]// 27a8
    move	t5,t6	// effectively-scratch[1] = scratch[2]		// 27ac
    sw	a0,0(v0)	// data[offset] ^= previous-scratch[1]		// 27b0
    move	t6,t7	// effectively-scratch[2] = scratch[3]		// 27b4
    sw	a1,4(v0)	// data[offset + 1] ^= previous-scratch[2]		// 27b8
    move	t7,s0   // effectively-scratch[3] = scratch[4]		// 27bc
    sw	a2,8(v0)	// data[offset + 2] ^= previous-scratch[3]		// 27c0
    move	s0,s1   // effectively-scratch[4] = scratch[5]		// 27c4
    sw	a3,12(v0)	// data[offset + 3] ^= previous-scratch[4]		// 27c8
    move	s1,s2	// effectively-scratch[5] = scratch[6]		// 27cc
    sw	t0,16(v0)	// data[offset + 4] ^= previous-scratch[5]		// 27d0
    move	s2,s3	// effectively-scratch[6] = scratch[7]		// 27d4
    sw	t1,20(v0)	// data[offset + 5] ^= previous-scratch[6]		// 27d8
    sw	t2,24(v0)	// data[offset + 6] ^= previous-scratch[7]		// 27dc
    bnez	t3,__2744		// 27e0
    move	s3,t4		// scratch[7] = data[offset + 7] ^ rodatakey[7] // 27e4
    sw	t4,28(sp)		// 27e8
    sw	s2,24(sp)		// 27ec
    sw	s1,20(sp)		// 27f0
    sw	s0,16(sp)		// 27f4
    sw	t7,12(sp)		// 27f8
    sw	t6,8(sp)		// 27fc
    sw	t5,4(sp)		// 2800
    sw	t9,0(sp)		// 2804

	// arrive here from 273c
	__2808:
    lw	s6,56(sp)		// 2808
    lw	s5,52(sp)		// 280c
    lw	s4,48(sp)		// 2810
    lw	s3,44(sp)		// 2814
    lw	s2,40(sp)		// 2818
    lw	s1,36(sp)		// 281c
    lw	s0,32(sp)		// 2820
    jr	ra		// 2824
    addiu	sp,sp,64		// 2828
.end func_268c_asm

.data
_key_282c:
.byte 0xa2, 0x6e, 0x14, 0x42, 0x85, 0x8e, 0x2c, 0x89
.byte 0x27, 0x6d, 0x9f, 0x9f, 0xc3, 0xed, 0x5f, 0x54
.byte 0xca, 0xc0, 0xe5, 0x09, 0x61, 0x7e, 0xfa, 0x2d
.byte 0xe6, 0x22, 0x53, 0x4e, 0xb9, 0x85, 0x91, 0xb1 // 2850

_data_3400:
/* g_crypt_key6 */
.byte 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.byte 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00 /* 3420 */

_data_3420:
.byte 0xa3, 0xe6, 0xfa, 0x56, 0x10, 0xc1, 0xe0, 0x56
.byte 0x9b, 0xeb, 0x8a, 0xf1, 0x9b, 0xcd, 0xa8, 0x27
.byte 0xc4, 0x67, 0x5a, 0x55, 0x0f, 0xf7, 0xb7, 0x19
.byte 0xe8, 0xec, 0x7d, 0x53, 0xdb, 0x01, 0x00, 0x00 /* 3440 */

_data_3440:
.byte 0x26, 0x61, 0xad, 0xef, 0x6e, 0x9d, 0x4c, 0x0a  /* 3448 */
.byte 0xf5, 0x6b, 0xc2, 0x19, 0xa4, 0x63, 0x95, 0x14  /* 3450 */
.byte 0xf4, 0x2f, 0xf2, 0x29, 0xf1, 0x1a, 0x73, 0x7e  /* 3458 */
.byte 0x3a, 0x85, 0xba, 0x32, 0x72, 0x01, 0x00, 0x00  /* 3460 */

_data_3460:
.byte 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.byte 0x00, 0x00, 0x00, 0x00 /* 3484 */

_data_3484:
.byte 0x20, 0xf9, 0xd7, 0x56, 0x30, 0x24, 0x55, 0xa9
.byte 0x7a, 0xd7, 0x25, 0xe5, 0xed, 0xf8, 0xb4, 0x36
.byte 0x41, 0xc5, 0x51, 0xaf

_firmware_signature_3498:
.byte 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
.byte 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x75   /* "3DUfw... */ /* 34a8 */

_signature_34a8:
.byte 0x08, 0x00, 0x00, 0x00

_signature_34ac:
.byte 0x08, 0x08, 0x00, 0x00

_signature_34b0:
.byte 0x3f, 0xad, 0xf8, 0xb0, 0x2e, 0xaf, 0x67, 0x49
.byte 0xb9, 0x85, 0x5f, 0x63, 0x4e, 0x5e, 0x8e, 0x2e

_unknown_data_2:
/* Think this is OS-related */
.byte 0xd4, 0x8a, 0xc2, 0xbf, 0x4c, 0x8d, 0xc2, 0xbf /* 34c8 */

_data_34c8:
.byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /* 34d0 */
.byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   /* 34d8 */
.byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   /* 34c0 */
.byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* 35c8 */

//.bss

//.lcomm __bss 5440

