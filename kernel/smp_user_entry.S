// Per-CPU context ownership: GSBASE is a supervisor-only Context pointer.
// No region-service or single-CPU saved-continuation globals are used.
.section .text,"xr"
.code64
.global smp_user_enter
smp_user_enter:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    mov r8, rdi
    mov r9, rsi
    mov r10, rdx
    mov rdi, rsp
    xor eax, eax
    mov ecx, 64
    rep stosq
    fxsave64 [rsp]
    mov [r10 + 8], rsp
    mov rax, cr3
    mov [r10 + 16], rax
    mov cr3, r8
    mov ax, 0x2b
    mov ds, ax
    mov es, ax
    fxrstor64 [r9 + 176]
    push qword ptr [r9 + 168]
    push qword ptr [r9 + 160]
    push qword ptr [r9 + 152]
    push qword ptr [r9 + 144]
    push qword ptr [r9 + 136]
    mov r15, [r9]
    mov r14, [r9 + 8]
    mov r13, [r9 + 16]
    mov r12, [r9 + 24]
    mov r11, [r9 + 32]
    mov r10, [r9 + 40]
    mov r8, [r9 + 56]
    mov rdi, [r9 + 64]
    mov rsi, [r9 + 72]
    mov rbp, [r9 + 80]
    mov rbx, [r9 + 88]
    mov rdx, [r9 + 96]
    mov rcx, [r9 + 104]
    mov rax, [r9 + 112]
    mov r9, [r9 + 48]
    swapgs
    iretq
.if {smp_timer}
.global smp_user_timer_67
smp_user_timer_67:
.if {smp_workload}
    cmp qword ptr [rsp + 8], 8
    je smp_workload_timer_drain
.endif
    push 0
    push 67
    jmp smp_user_trap_common
.endif
.global smp_user_ipi_66
smp_user_ipi_66:
    push 0
    push 66
    jmp smp_user_trap_common
.global smp_user_yield_128
smp_user_yield_128:
    push 0
    push 128
    jmp smp_user_trap_common
.global smp_user_fault_13
smp_user_fault_13:
    push 13
    jmp smp_user_trap_common
.global smp_user_fault_14
smp_user_fault_14:
    push 14
smp_user_trap_common:
    cmp qword ptr [rsp + 24], 0x33
    jne smp_user_unexpected
    swapgs
    lfence
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
    fxrstor64 [rip + smp_user_reset_fp]
    mov rdi, rbx
    mov rsi, rsp
    mov rdx, qword ptr gs:[0]
    call smp_user_capture
    // Capture returns only to this CPU's protected continuation.
    mov rdx, qword ptr gs:[0]
    mov rax, [rdx + 16]
    mov cr3, rax
    mov ax, 16
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov rsp, [rdx + 8]
    fxrstor64 [rsp]
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.global smp_user_unexpected
smp_user_unexpected:
    cli
    and rsp, -16
    call smp_ap_fail
1:  hlt
    jmp 1b

.if {smp_workload}
// Only the AP's post-INT128 drain window enables IRQs at CPL0. Preserve the
// supervisor continuation, including flags and any live legacy FP state.
smp_workload_timer_drain:
    cld
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    mov rbx, rsp
    and rsp, -16
    sub rsp, 512
    fxsave64 [rsp]
    call smp_workload_drain
    fxrstor64 [rsp]
    mov rsp, rbx
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    iretq
.endif

.section .text$smpuser,"xr"
.balign 4096
.global smp_user_program_start
smp_user_program_start:
.global smp_user_bsp_start
smp_user_bsp_start:
    mov ax, 0x2b
    mov gs, ax
    cmp qword ptr [rdi + 8], r13
    jne smp_user_bad
    jmp smp_user_loop_start
.global smp_user_warmup_start
smp_user_warmup_start:
    mov ax, 0x2b
    mov gs, ax
    cmp qword ptr [rdi + 8], r13
    jne smp_user_bad
2:  lock inc qword ptr [rdi]
    pause
    dec rcx
    jnz 2b
.global smp_user_warmup_end
smp_user_warmup_end:
.global smp_user_yield
smp_user_yield:
    int 128
.global smp_user_after_yield
smp_user_after_yield:
    jmp smp_user_loop_start
.global smp_user_peer_fault
smp_user_peer_fault:
    mov rax, qword ptr [rsi]
    ud2
.global smp_user_forged_fault
smp_user_forged_fault:
    int 66
    ud2
.global smp_user_loop_start
smp_user_loop_start:
    lock inc qword ptr [rdi]
    pause
    jmp smp_user_loop_start
.global smp_user_loop_end
smp_user_loop_end:
smp_user_bad:
    ud2
    .org smp_user_program_start + 4096
.global smp_user_program_end
smp_user_program_end:

.if {smp_workload}
.section .text$smpworkload,"xr"
.balign 4096
.global smp_workload_program_start
smp_workload_program_start:
.global smp_workload_user_start
smp_workload_user_start:
    mov ax, 0x2b
    mov gs, ax
    cmp qword ptr [rdi + 8], r13
    jne smp_workload_bad
.global smp_workload_loop
smp_workload_loop:
    lock inc qword ptr [rdi]
.global smp_workload_after_inc
smp_workload_after_inc:
    add r10, r12
.global smp_workload_after_sum
smp_workload_after_sum:
    pause
.global smp_workload_before_dec
smp_workload_before_dec:
    dec rcx
.global smp_workload_after_dec
smp_workload_after_dec:
    jnz smp_workload_loop
.global smp_workload_complete
smp_workload_complete:
    int 128
.global smp_workload_complete_return
smp_workload_complete_return:
smp_workload_bad:
    ud2
    .org smp_workload_program_start + 4096
.global smp_workload_program_end
smp_workload_program_end:
.endif
