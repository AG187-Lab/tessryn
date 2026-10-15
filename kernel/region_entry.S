// Original cooperative context entry. Layout is asserted by region_runtime.rs.
// Each entry saves the kernel continuation; each trap returns to that owner.
.text
.global region_resume_user
region_resume_user:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    xor r9d, r9d
.Lregion_kernel_zero:
    mov qword ptr [rsp + r9], 0
    add r9, 8
    cmp r9, 512
    jne .Lregion_kernel_zero
    fxsave64 [rsp]
    mov qword ptr [rip + k02_kernel_fp_restored], 0
    mov [rip + k02_saved_kernel_rsp], rsp
    mov rax, cr3
    mov [rip + k02_saved_kernel_cr3], rax
    mov r11, rsi
    mov cr3, rdi
    mov ax, 0x2b
    mov ds, ax
    mov es, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    fxrstor64 [r11 + 176]
    push qword ptr [r11 + 168]
    push qword ptr [r11 + 160]
    push qword ptr [r11 + 152]
    push qword ptr [r11 + 144]
    push qword ptr [r11 + 136]
    mov r15, [r11]
    mov r14, [r11 + 8]
    mov r13, [r11 + 16]
    mov r12, [r11 + 24]
    mov r10, [r11 + 40]
    mov r9, [r11 + 48]
    mov r8, [r11 + 56]
    mov rdi, [r11 + 64]
    mov rsi, [r11 + 72]
    mov rbp, [r11 + 80]
    mov rbx, [r11 + 88]
    mov rdx, [r11 + 96]
    mov rcx, [r11 + 104]
    mov rax, [r11 + 112]
    mov r11, [r11 + 32]
    iretq
