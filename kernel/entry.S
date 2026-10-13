// Original x86-64 entry and exception assembly; no imported deployment code.
.text
.global kernel_enter
kernel_enter:
    cli
    cld
    mov rsp, rcx
    and rsp, -16
    xor rbp, rbp
    mov rdi, rdx
    call kernel_main
.Lentry_halt:
    cli
    hlt
    jmp .Lentry_halt

.global load_gdt
load_gdt:
    lgdt [rdi]
    push 8
    lea rax, [rip + .Lnew_cs]
    push rax
    retfq
.Lnew_cs:
    mov ax, 16
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    mov ax, 24
    ltr ax
    ret

.global probe_int3
probe_int3:
    mov rax, 0x5445535352594e01
    movq xmm0, rax
    mov rax, 0x494e543350524f42
    movq xmm15, rax
    int3
    movq rax, xmm0
    mov rcx, 0x5445535352594e01
    cmp rax, rcx
    jne .Lprobe_bad
    movq rax, xmm15
    mov rcx, 0x494e543350524f42
    cmp rax, rcx
    jne .Lprobe_bad
    mov eax, 1
    ret
.Lprobe_bad:
    xor eax, eax
    ret

.global smash_probe_fp
smash_probe_fp:
    pxor xmm0, xmm0
    pxor xmm15, xmm15
    ret

.global exception_0
exception_0:
    push 0
    push 0
    jmp exception_common
.global exception_1
exception_1:
    push 0
    push 1
    jmp exception_common
.global exception_2
exception_2:
    push 0
    push 2
    jmp exception_common
.global exception_3
exception_3:
    push 0
    push 3
    jmp exception_common
.global exception_4
exception_4:
    push 0
    push 4
    jmp exception_common
.global exception_5
exception_5:
    push 0
    push 5
    jmp exception_common
.global exception_6
exception_6:
    push 0
    push 6
    jmp exception_common
.global exception_7
exception_7:
    push 0
    push 7
    jmp exception_common
.global exception_8
exception_8:
    push 8
    jmp exception_common
.global exception_9
exception_9:
    push 0
    push 9
    jmp exception_common
.global exception_10
exception_10:
    push 10
    jmp exception_common
.global exception_11
exception_11:
    push 11
    jmp exception_common
.global exception_12
exception_12:
    push 12
    jmp exception_common
.global exception_13
exception_13:
    push 13
    jmp exception_common
.global exception_14
exception_14:
    push 14
    jmp exception_common
.global exception_15
exception_15:
    push 0
    push 15
    jmp exception_common
.global exception_16
exception_16:
    push 0
    push 16
    jmp exception_common
.global exception_17
exception_17:
    push 17
    jmp exception_common
.global exception_18
exception_18:
    push 0
    push 18
    jmp exception_common
.global exception_19
exception_19:
    push 0
    push 19
    jmp exception_common
.global exception_20
exception_20:
    push 0
    push 20
    jmp exception_common
.global exception_21
exception_21:
    push 21
    jmp exception_common
.global exception_22
exception_22:
    push 0
    push 22
    jmp exception_common
.global exception_23
exception_23:
    push 0
    push 23
    jmp exception_common
.global exception_24
exception_24:
    push 0
    push 24
    jmp exception_common
.global exception_25
exception_25:
    push 0
    push 25
    jmp exception_common
.global exception_26
exception_26:
    push 0
    push 26
    jmp exception_common
.global exception_27
exception_27:
    push 0
    push 27
    jmp exception_common
.global exception_28
exception_28:
    push 0
    push 28
    jmp exception_common
.global exception_29
exception_29:
    push 29
    jmp exception_common
.global exception_30
exception_30:
    push 30
    jmp exception_common
.global exception_31
exception_31:
    push 0
    push 31
    jmp exception_common
.global exception_unexpected
exception_unexpected:
    push 0
    push 255
    jmp exception_common

exception_common:
    cld
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    mov rbx, rsp
    and rsp, -16
    sub rsp, 512
    fxsave64 [rsp]
    call exception_handler
    fxrstor64 [rsp]
    mov rsp, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    add rsp, 16
    iretq
.section .rdata
.p2align 3
.global exception_addresses
exception_addresses:
    .quad exception_0
    .quad exception_1
    .quad exception_2
    .quad exception_3
    .quad exception_4
    .quad exception_5
    .quad exception_6
    .quad exception_7
    .quad exception_8
    .quad exception_9
    .quad exception_10
    .quad exception_11
    .quad exception_12
    .quad exception_13
    .quad exception_14
    .quad exception_15
    .quad exception_16
    .quad exception_17
    .quad exception_18
    .quad exception_19
    .quad exception_20
    .quad exception_21
    .quad exception_22
    .quad exception_23
    .quad exception_24
    .quad exception_25
    .quad exception_26
    .quad exception_27
    .quad exception_28
    .quad exception_29
    .quad exception_30
    .quad exception_31
