.text
.globl dbvf_prefilter
.type dbvf_prefilter, @function
.p2align 4
dbvf_prefilter:
    xor %r8d, %r8d
    cmp $19, %rsi
    jb .Lret
    lea -19(%rsi), %r9
.Lblock:
    cmp %r9, %r8
    ja .Lret
    movdqu (%rdi,%r8), %xmm0
    movdqu 1(%rdi,%r8), %xmm1
    movdqu 2(%rdi,%r8), %xmm2
    movdqu 3(%rdi,%r8), %xmm3
    pxor %xmm7, %xmm7
    xor %r10d, %r10d
.Lpfx:
    cmp %rcx, %r10
    jae .Lcheck
    movd (%rdx,%r10,4), %xmm5
    pshufd $0, %xmm5, %xmm5
    movdqa %xmm0, %xmm6
    pcmpeqd %xmm5, %xmm6
    por %xmm6, %xmm7
    movdqa %xmm1, %xmm6
    pcmpeqd %xmm5, %xmm6
    por %xmm6, %xmm7
    movdqa %xmm2, %xmm6
    pcmpeqd %xmm5, %xmm6
    por %xmm6, %xmm7
    movdqa %xmm3, %xmm6
    pcmpeqd %xmm5, %xmm6
    por %xmm6, %xmm7
    inc %r10
    jmp .Lpfx
.Lcheck:
    pmovmskb %xmm7, %eax
    test %eax, %eax
    jnz .Lhit
    add $16, %r8
    jmp .Lblock
.Lhit:
    mov %r8, %rax
    ret
.Lret:
    mov %r8, %rax
    ret
.size dbvf_prefilter, .-dbvf_prefilter
.section .note.GNU-stack,"",@progbits

# size_t dbvf_prefilter(const uint8_t *buf, size_t len, const uint32_t *pfx, size_t npfx)
# rdi=buf rsi=len rdx=pfx rcx=npfx, returns offset of first 16-byte block holding a candidate token start
# returns the first unprocessed offset when nothing matches, the c side scans that tail itself
# four shifted loads cover every start position in the block, each dword is compared against every prefix
# i love asm :3
# https://hollowlinux.cc!
