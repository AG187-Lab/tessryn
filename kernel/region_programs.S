// Two original image-bound programs. All requests are constructed at CPL3.
// No kernel recipe overwrites their request pages between continuations.
.equ REGION_REQUEST, 0x10000f000
.equ REGION_DATA, 0x100004000
.equ REGION_SEED, 0x544553535245474e
.equ REGION_WRITTEN, 0x1122334455667788

.macro REQUEST who, op
    mov eax, \op
    call region_\who\()_request
.endm
.macro CAP domain
    mov qword ptr [rdi + 32], r12
    mov qword ptr [rdi + 40], \domain
.endm
.macro MAP rights
    mov qword ptr [rdi + 64], 4096
    movabs rax, REGION_DATA
    mov qword ptr [rdi + 72], rax
    mov qword ptr [rdi + 80], \rights
.endm
.macro TRAP who, name, status=0
    call region_\who\()_snapshot
    int 0x80
.global region_\who\()_\name\()_trap
region_\who\()_\name\()_trap:
    cmp rax, \status
    jne region_\who\()_fail
    call region_\who\()_check
.endm

.macro HELPERS who, fpword, fpexponent, xmmword
region_\who\()_request:
    inc r15
    movabs rdi, REGION_REQUEST
    mov dword ptr [rdi + 24], eax
    xor eax, eax
    mov qword ptr [rdi + 12], rax
    mov dword ptr [rdi + 28], eax
    mov qword ptr [rdi + 32], rax
    mov qword ptr [rdi + 40], rax
    mov qword ptr [rdi + 48], rax
    mov qword ptr [rdi + 56], rax
    mov qword ptr [rdi + 64], rax
    mov qword ptr [rdi + 72], rax
    mov qword ptr [rdi + 80], rax
    mov qword ptr [rdi + 88], rax
    movabs rax, 0x314e475253534554
    mov qword ptr [rdi], rax
    mov word ptr [rdi + 8], 1
    mov word ptr [rdi + 10], 96
    mov qword ptr [rdi + 16], r15
    mov esi, 96
    ret
region_\who\()_snapshot:
    movabs rax, REGION_REQUEST
    mov [rax + 1024], r15
    mov [rax + 1032], r14
    mov [rax + 1040], r13
    mov [rax + 1048], r12
    mov [rax + 1056], r11
    mov [rax + 1064], rdi
    mov [rax + 1072], rsi
    mov [rax + 1080], rbp
    mov [rax + 1088], rbx
    lea r11, [rsp + 8]
    mov [rax + 1096], r11
    mov r11, [rax + 1056]
    ret
region_\who\()_check:
    movabs rax, REGION_REQUEST
    cmp r15, [rax + 1024]
    jne region_\who\()_fail
    cmp r14, [rax + 1032]
    jne region_\who\()_fail
    cmp r13, [rax + 1040]
    jne region_\who\()_fail
    cmp r12, [rax + 1048]
    jne region_\who\()_fail
    cmp r11, [rax + 1056]
    jne region_\who\()_fail
    cmp rdi, [rax + 1064]
    jne region_\who\()_fail
    cmp rsi, [rax + 1072]
    jne region_\who\()_fail
    cmp rbp, [rax + 1080]
    jne region_\who\()_fail
    cmp rbx, [rax + 1088]
    jne region_\who\()_fail
    lea r11, [rsp + 8]
    cmp r11, [rax + 1096]
    jne region_\who\()_fail
    fxsave64 [rax + 512]
    movabs r11, \fpword
    cmp [rax + 544], r11
    jne region_\who\()_fail
    cmp word ptr [rax + 552], \fpexponent
    jne region_\who\()_fail
    cmp word ptr [rax + 514], 0x3800
    jne region_\who\()_fail
    cmp byte ptr [rax + 516], 0x80
    jne region_\who\()_fail
    cmp qword ptr [rax + 912], \xmmword
    jne region_\who\()_fail
    cmp qword ptr [rax + 920], \xmmword
    jne region_\who\()_fail
    mov r11, [rax + 1056]
    ret
.global region_\who\()_fail
region_\who\()_fail:
    ud2
.endm

.macro INITIAL who
    // Only R12=provisioned cap and R13=scenario are declared first-entry inputs.
    test rax, rax
    jne region_\who\()_fail
    mov rax, rbx
    or rax, rcx
    or rax, rdx
    or rax, rbp
    or rax, rsi
    or rax, rdi
    or rax, r8
    or rax, r9
    or rax, r10
    or rax, r11
    or rax, r14
    or rax, r15
    jne region_\who\()_fail
    movabs rdi, REGION_REQUEST
    fxsave64 [rdi + 512]
    cmp word ptr [rdi + 512], 0x37f
    jne region_\who\()_fail
    cmp dword ptr [rdi + 536], 0x1f80
    jne region_\who\()_fail
    cmp byte ptr [rdi + 516], 0
    jne region_\who\()_fail
    mov ecx, 384
    lea rdi, [rdi + 544]
    xor eax, eax
    repe scasb
    jne region_\who\()_fail
.endm

.p2align 12
.global region_program_a_start
region_program_a_start:
    INITIAL a
    movabs rbx, 0x4141414141414141
    movabs rbp, 0xaaaaaaaa55555555
    fld1
    pcmpeqd xmm15, xmm15
    REQUEST a, 2
    CAP 1
    MAP 7
    TRAP a, map
    mov r14, rdx
    movabs rax, REGION_REQUEST
    mov [rax + 2064], r14
    movabs rax, REGION_DATA
.global region_a_read
region_a_read:
    mov rdx, [rax]
    movabs rcx, REGION_SEED
    cmp rdx, rcx
    jne region_a_fail
    movabs rcx, REGION_WRITTEN
    mov [rax + 8], rcx
    // The ownership reference forbids concurrent aliases of a WRITE lease.
    // Retire it before sharing and keep only a READ mapping while B runs.
    REQUEST a, 5
    mov [rdi + 48], r14
    TRAP a, writable_unmap
    REQUEST a, 2
    CAP 1
    MAP 5
    TRAP a, readonly_remap
    mov r14, rdx
    REQUEST a, 3
    CAP 1
    mov qword ptr [rdi + 48], 2
    mov qword ptr [rdi + 64], 4096
    mov qword ptr [rdi + 80], 5
    TRAP a, delegate
    REQUEST a, 8
    TRAP a, first_yield
    cmp r13, 2
    je .La_authority
    cmp r13, 1
    jne .La_share
    REQUEST a, 4
    CAP 1
    TRAP a, revoke
    jmp .La_second_yield
.La_share:
    REQUEST a, 7
    TRAP a, accounting
.La_second_yield:
    REQUEST a, 8
    TRAP a, second_yield
    REQUEST a, 5
    mov [rdi + 48], r14
    cmp r13, 1
    je .La_old_mapping
    TRAP a, unmap
    jmp .La_release
.La_old_mapping:
    TRAP a, revoked_mapping, 5
    jmp .La_release

.La_authority:
    REQUEST a, 7
    lea rdi, [rdi + 4048]
    TRAP a, cross_page, 7
    REQUEST a, 7
    movabs rdi, 0x100010000
    TRAP a, unmapped_buffer, 7
    REQUEST a, 7
    mov rdi, -8
    TRAP a, overflow_buffer, 13
    REQUEST a, 7
    mov esi, 88
    TRAP a, short_buffer, 1
    REQUEST a, 7
    mov byte ptr [rdi], 0
    TRAP a, bad_magic, 1
    REQUEST a, 7
    mov word ptr [rdi + 8], 2
    TRAP a, bad_version, 2
    REQUEST a, 99
    TRAP a, bad_operation, 3
    // Task plumbing capabilities are kernel-private even in our own namespace.
    REQUEST a, 4
    movabs rax, 0x100000000
    mov [rdi + 32], rax
    mov qword ptr [rdi + 40], 1
    TRAP a, private_stack, 4
    REQUEST a, 2
    movabs rax, 0x100000001
    mov [rdi + 32], rax
    mov qword ptr [rdi + 40], 1
    MAP 5
    TRAP a, private_request, 4
    REQUEST a, 5
    mov rax, [rdi + 2064]
    mov [rdi + 48], rax
    TRAP a, stale_mapping, 5
    REQUEST a, 2
    CAP 2
    MAP 5
    TRAP a, foreign, 4
    REQUEST a, 2
    CAP 1
    inc dword ptr [rdi + 36]
    MAP 5
    TRAP a, stale, 5
    REQUEST a, 2
    CAP 1
    MAP 5
    movabs rax, 0x100002000
    mov [rdi + 72], rax
    TRAP a, collision, 14
    REQUEST a, 6
    CAP 1
    TRAP a, busy_release, 12
    REQUEST a, 8
    TRAP a, authority_yield
    REQUEST a, 5
    mov [rdi + 48], r14
    TRAP a, authority_unmap
.La_release:
    REQUEST a, 6
    CAP 1
    TRAP a, release
    cmp r13, 2
    jne .La_done
    // Reuse must return a new generation and a scrubbed backing page.
    movabs rax, REGION_REQUEST
    mov [rax + 2048], r12
    REQUEST a, 1
    mov qword ptr [rdi + 64], 4096
    TRAP a, allocate
    cmp rcx, 1
    jne region_a_fail
    cmp r12, rdx
    je region_a_fail
    mov r12, rdx
    REQUEST a, 6
    mov rax, [rdi + 2048]
    mov [rdi + 32], rax
    mov qword ptr [rdi + 40], 1
    TRAP a, old_cap, 5
    REQUEST a, 2
    CAP 1
    MAP 7
    TRAP a, remap
    mov r14, rdx
    movabs rax, REGION_DATA
.global region_a_scrub_read
region_a_scrub_read:
    cmp qword ptr [rax], 0
    jne region_a_fail
    REQUEST a, 5
    mov [rdi + 48], r14
    TRAP a, reunmap
    REQUEST a, 6
    CAP 1
    TRAP a, rerelease
.La_done:
    REQUEST a, 7
    TRAP a, final_accounting
    cmp r8, 2
    jne region_a_fail
    cmp r9, 2
    jne region_a_fail
    test r10, r10
    jne region_a_fail
    REQUEST a, 9
    TRAP a, exit
    ud2
    HELPERS a, 0x8000000000000000, 0x3fff, -1
    .zero 4096 - (. - region_program_a_start)
.global region_program_a_end
region_program_a_end:

.p2align 12
.global region_program_b_start
region_program_b_start:
    INITIAL b
    movabs rbx, 0x4242424242424242
    movabs rbp, 0xbbbbbbbb66666666
    fldz
    pcmpeqd xmm15, xmm15
    psllq xmm15, 1
    REQUEST b, 2
    CAP 2
    MAP 5
    TRAP b, map
    mov r14, rdx
    movabs rax, REGION_DATA
.global region_b_read
region_b_read:
    mov rdx, [rax]
    movabs rcx, REGION_SEED
    cmp rdx, rcx
    jne region_b_fail
    mov rdx, [rax + 8]
    movabs rcx, REGION_WRITTEN
    cmp rdx, rcx
    jne region_b_fail
    REQUEST b, 7
    TRAP b, read_confirmed
    REQUEST b, 8
    TRAP b, first_yield
    cmp r13, 2
    je .Lb_authority
    movabs rdi, REGION_DATA
    cmp r13, 1
    je .Lb_stale
.global region_b_write_fault
region_b_write_fault:
    mov qword ptr [rdi], 0x1234
    jmp region_b_fail
.Lb_stale:
.global region_b_stale_fault
region_b_stale_fault:
    mov rax, [rdi]
    jmp region_b_fail
.Lb_authority:
    REQUEST b, 5
    movabs rax, 0x200000001
    mov [rdi + 48], rax
    TRAP b, foreign_mapping, 4
    REQUEST b, 2
    CAP 1
    MAP 5
    TRAP b, foreign, 4
    REQUEST b, 2
    CAP 2
    MAP 7
    TRAP b, write_authority, 9
    REQUEST b, 5
    mov [rdi + 48], r14
    TRAP b, unmap
    REQUEST b, 6
    CAP 2
    TRAP b, busy_release, 12
    REQUEST b, 9
    TRAP b, exit
    ud2
    HELPERS b, 0, 0, -2
    .zero 4096 - (. - region_program_b_start)
.global region_program_b_end
region_program_b_end:
