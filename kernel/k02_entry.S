// Original bounded user-probe transition. Intel 64 privilege frames; SysV64.
.text
.global k02_enter_user
k02_enter_user:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    sub rsp, 512
    fxsave64 [rsp]
    mov [rip + k02_saved_kernel_rsp], rsp
    mov rax, cr3
    mov [rip + k02_saved_kernel_cr3], rax
    mov rax, rdi
    mov r10, rsi
    mov r11, rdx
    mov rdi, rcx
    mov rsi, r8
    mov cr3, rax
    mov ax, 0x2b
    mov ds, ax
    mov es, ax
    push 0x2b
    push r11
    push 2
    push 0x33
    push r10
    iretq

.global k02_return_kernel
k02_return_kernel:
    cli
    cld
    mov ax, 16
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov rax, [rip + k02_saved_kernel_cr3]
    mov cr3, rax
    mov rsp, [rip + k02_saved_kernel_rsp]
    fxrstor64 [rsp]
    add rsp, 512
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    mov eax, 1
    ret

.global exception_k02_return
exception_k02_return:
    push 0
    push 128
    jmp exception_common

// No address relocations or privileged I/O occur in the copied user page.
// Arguments come from protected kernel state, not a user-supplied identity.
.p2align 12
.global k02_user_code_start
k02_user_code_start:
.global k02_probe_own_write
k02_probe_own_write:
    mov qword ptr [rdi + 8], rsi
.global k02_probe_own_read
k02_probe_own_read:
    mov rax, qword ptr [rdi]
.global k02_probe_own_return
k02_probe_own_return:
    int 0x80
    ud2
.global k02_probe_foreign_read
k02_probe_foreign_read:
    mov rax, qword ptr [rdi]
    int 0x80
    ud2
.global k02_probe_kernel_read
k02_probe_kernel_read:
    mov rax, qword ptr [rdi]
    int 0x80
    ud2
.global k02_probe_readonly_write
k02_probe_readonly_write:
    mov qword ptr [rdi], rsi
    int 0x80
    ud2
    .zero 4096 - (. - k02_user_code_start)
.global k02_user_code_end
k02_user_code_end:
