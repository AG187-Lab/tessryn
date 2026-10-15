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
    // QEMU 11.1.2 does not populate the FOP field in FXSAVE. Initialize the
    // complete image using GPR stores before capturing FP state, so unwritten
    // capture holes cannot contain stale stack bytes. Keep comparing FOP on
    // implementations that populate it; no architectural field is excluded.
    xor r9d, r9d
.Lk02_save_zero:
    mov qword ptr [rsp + r9], 0
    add r9, 8
    cmp r9, 512
    jne .Lk02_save_zero
    fxsave64 [rsp]
    mov qword ptr [rip + k02_kernel_fp_restored], 0
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
    // The original kernel FP image is retained at the saved kernel RSP.
    // Reset all legacy user-visible FP data, not just the x87 tags. This
    // profile rejects OSXSAVE before entry; AVX/extended state is not admitted.
    .if {matrix_test}
    // Regression challenge: the original kernel image is already saved.
    // Dirty every legacy FP data register before applying the reset image so
    // the controlled user snapshot cannot pass merely because entry was clean.
    fninit
    .rept 8
    fld1
    .endr
    pcmpeqd xmm0, xmm0
    pcmpeqd xmm1, xmm1
    pcmpeqd xmm2, xmm2
    pcmpeqd xmm3, xmm3
    pcmpeqd xmm4, xmm4
    pcmpeqd xmm5, xmm5
    pcmpeqd xmm6, xmm6
    pcmpeqd xmm7, xmm7
    pcmpeqd xmm8, xmm8
    pcmpeqd xmm9, xmm9
    pcmpeqd xmm10, xmm10
    pcmpeqd xmm11, xmm11
    pcmpeqd xmm12, xmm12
    pcmpeqd xmm13, xmm13
    pcmpeqd xmm14, xmm14
    pcmpeqd xmm15, xmm15
    // Force every non-input GPR dirty as well. The snapshot independently
    // checks that the clear sequence below removes these challenge values.
    mov rax, -1
    mov rbx, -1
    mov rcx, -1
    mov rdx, -1
    mov rbp, -1
    mov r8, -1
    mov r9, -1
    mov r10, -1
    mov r11, -1
    mov r12, -1
    mov r13, -1
    mov r14, -1
    mov r15, -1
    .endif
    fxrstor64 [rip + k02_reset_fp]
    // RDI/RSI are the two intentional probe inputs. No other kernel general
    // register value crosses this privilege boundary. IRET restores RFLAGS=2.
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    xor ebp, ebp
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d
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
    // Compare actual restored architectural fields with the original image.
    // Reserved FXSAVE bytes are not architectural state and were not written
    // by the initial save: skip byte 5 and each x87 slot's six padding bytes.
    lea rdx, [rip + k02_restored_fp]
    xor r9d, r9d
.Lk02_restored_zero:
    mov qword ptr [rdx + r9], 0
    add r9, 8
    cmp r9, 512
    jne .Lk02_restored_zero
    fxsave64 [rdx]
    xor ecx, ecx
.Lk02_fp_compare:
    cmp ecx, 416
    jae .Lk02_fp_verified
    cmp ecx, 5
    je .Lk02_fp_next
    cmp ecx, 32
    jb .Lk02_fp_byte
    cmp ecx, 160
    jae .Lk02_fp_byte
    mov eax, ecx
    and eax, 15
    cmp eax, 10
    jae .Lk02_fp_next
.Lk02_fp_byte:
    mov al, byte ptr [rsp + rcx]
    cmp al, byte ptr [rdx + rcx]
    jne .Lk02_fp_restore_failed
.Lk02_fp_next:
    inc ecx
    jmp .Lk02_fp_compare
.Lk02_fp_verified:
    mov qword ptr [rip + k02_kernel_fp_restored], 1
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
.Lk02_fp_restore_failed:
    mov rdi, rcx
    call k02_fp_restore_failure
    ud2

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
.global k02_probe_kernel_read_return
k02_probe_kernel_read_return:
    ud2
.global k02_probe_readonly_write
k02_probe_readonly_write:
    mov qword ptr [rdi], rsi
    int 0x80
.global k02_probe_readonly_write_return
k02_probe_readonly_write_return:
    ud2

// Generic matrix probes share the same image-owned page. Keep the preceding
// first-slice labels at their original offsets. Each return/trap label denotes
// the exact RIP saved by INT80, not the interrupt instruction's address.
.global k02_probe_read
k02_probe_read:
    mov rax, qword ptr [rdi]
    int 0x80
.global k02_probe_read_return
k02_probe_read_return:
    ud2
.global k02_probe_write
k02_probe_write:
    mov qword ptr [rdi], rsi
    int 0x80
.global k02_probe_write_return
k02_probe_write_return:
    ud2
.global k02_probe_request
k02_probe_request:
    // RDI is the request pointer; RSI retains the claimed caller/operation.
    // Protected kernel state supplies actual dispatch authority.
    int 0x80
.global k02_probe_request_trap
k02_probe_request_trap:
    ud2

// Every matrix fault has a distinct image-bound instruction. Return labels
// also bind unexpected successful accesses to their exact controlled trap.
.macro K02_READ_PROBE name
.global k02_probe_\name
k02_probe_\name:
    mov rax, qword ptr [rdi]
    int 0x80
.global k02_probe_\name\()_return
k02_probe_\name\()_return:
    ud2
.endm
.macro K02_WRITE_PROBE name
.global k02_probe_\name
k02_probe_\name:
    mov qword ptr [rdi], rsi
    int 0x80
.global k02_probe_\name\()_return
k02_probe_\name\()_return:
    ud2
.endm
K02_READ_PROBE unauthorized_read
K02_READ_PROBE guard_read
K02_WRITE_PROBE kernel_write
K02_READ_PROBE policy_read
K02_WRITE_PROBE policy_write
K02_READ_PROBE page_table_read
K02_WRITE_PROBE page_table_write
K02_READ_PROBE recursive_B_read
K02_WRITE_PROBE recursive_B_write
K02_READ_PROBE recursive_D_read
K02_WRITE_PROBE recursive_D_write
K02_READ_PROBE reuse_B_read
K02_WRITE_PROBE reuse_B_write

// Append this independent snapshot so historical controlled load/store labels
// retain their offsets. Only the authorized request page is written. Neither
// FXSAVE nor these MOVs changes the general/FP state being observed.
.global k02_probe_boundary_snapshot
k02_probe_boundary_snapshot:
    fxsave64 [rdi]
    mov qword ptr [rdi + 512], r15
    mov qword ptr [rdi + 520], r14
    mov qword ptr [rdi + 528], r13
    mov qword ptr [rdi + 536], r12
    mov qword ptr [rdi + 544], r11
    mov qword ptr [rdi + 552], r10
    mov qword ptr [rdi + 560], r9
    mov qword ptr [rdi + 568], r8
    mov qword ptr [rdi + 576], rdi
    mov qword ptr [rdi + 584], rsi
    mov qword ptr [rdi + 592], rbp
    mov qword ptr [rdi + 600], rbx
    mov qword ptr [rdi + 608], rdx
    mov qword ptr [rdi + 616], rcx
    mov qword ptr [rdi + 624], rax
    mov qword ptr [rdi + 632], rsp
    int 0x80
.global k02_probe_boundary_snapshot_return
k02_probe_boundary_snapshot_return:
    ud2
    .zero 4096 - (. - k02_user_code_start)
.global k02_user_code_end
k02_user_code_end:
