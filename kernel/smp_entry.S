// Original relocatable SIPI template. Only the allowlisted data/far-pointer
// words are patched by the BSP; all internal references are page-relative.
.section .text$smptramp,"xr"
.balign 4096
.global smp_trampoline_start
smp_trampoline_start:
.code16
    cli
    cld
    mov ax, cs
    mov ds, ax
    // No stack use until the 64-bit private stack is installed.
    lgdt [0x838]
    mov eax, 0x620
    mov cr4, eax
    mov eax, dword ptr [0x800]
    mov cr3, eax
    mov ecx, 0xc0000080
    rdmsr
    or eax, 0x900
    wrmsr
    mov eax, 0x80010033
    mov cr0, eax
    // Operand-size-prefixed far jump to a patched physical offset, CS=8.
    .byte 0x66, 0xea
.global smp_trampoline_far
smp_trampoline_far:
    .long 0
    .word 8
.code64
.global smp_trampoline_long
smp_trampoline_long:
    mov ax, 16
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    mov rsp, qword ptr [rip + smp_trampoline_stack]
    and rsp, -16
    xor ebp, ebp
    // INIT may retain FP data: reset the entire legacy image, not just FCW.
    fxrstor64 [rip + smp_trampoline_fp]
    mov rax, qword ptr [rip + smp_trampoline_entry]
    call rax
1:  cli
    hlt
    jmp 1b
    .org smp_trampoline_start + 0x800
    .long 0 // CR3, deliberately restricted to <4 GiB.
    .long 0
smp_trampoline_entry:
    .quad 0
smp_trampoline_stack:
    .quad 0
    .quad 0
smp_trampoline_gdt:
    .quad 0, 0x00af9a000000ffff, 0x00cf92000000ffff
smp_trampoline_gdtr:
    .word 23
    .long 0
    .balign 16
smp_trampoline_fp:
    .word 0x37f
    .zero 22
    .long 0x1f80
    .zero 484
    .org smp_trampoline_start + 4096
.global smp_trampoline_end
smp_trampoline_end:

.section .text,"xr"
.code64
.global smp_heartbeat_start
.global smp_heartbeat_end
smp_heartbeat_start:
    lock inc qword ptr [rdi]
    pause
    jmp smp_heartbeat_start
smp_heartbeat_end:
    ud2
.global smp_load_gdt
smp_load_gdt:
    lgdt [rdi]
    push 8
    lea rax, [rip + 2f]
    push rax
    retfq
2:  mov ax, 16
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov ax, 24
    ltr ax
    ret

.global smp_ipi_64
smp_ipi_64:
    push 64
    jmp smp_interrupt_common
.global smp_stop_65
smp_stop_65:
    push 65
smp_interrupt_common:
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
    mov rbx, rsp
    and rsp, -16
    sub rsp, 512
    mov rdi, rsp
    xor eax, eax
    mov ecx, 64
    rep stosq
    fxsave64 [rsp]
    fxrstor64 [rip + smp_trampoline_fp]
    mov rdi, [rbx + 120]
    mov rsi, rbx
    call smp_interrupt
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
    add rsp, 8
    iretq
.global smp_unexpected
smp_unexpected:
    cli
    and rsp, -16
    call smp_ap_fail
3:  hlt
    jmp 3b
.global smp_spurious
smp_spurious:
    iretq
