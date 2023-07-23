[section .text]

global juptuneSwapFiberAsm

struc fiber_t_linux_amd64_sysv
    .ret: resq 1
    .rbx: resq 1
    .rbp: resq 1
    .rsp: resq 1
    .r12: resq 1
    .r13: resq 1
    .r14: resq 1
    .r15: resq 1
endstruc

;                   void (Fiber* from, Fiber* to)
; linux_amd64_sysv:              rdi          rsi
juptuneSwapFiberAsm:
    %ifdef linux_amd64_sysv
        lea rax, [rsp+8] ; Stack pointer without return address
        mov r8, [rsp]    ; Return address
        mov [rdi+fiber_t_linux_amd64_sysv.ret], r8
        mov [rdi+fiber_t_linux_amd64_sysv.rsp], rax
        mov [rdi+fiber_t_linux_amd64_sysv.rbx], rbx
        mov [rdi+fiber_t_linux_amd64_sysv.rbp], rbp
        mov [rdi+fiber_t_linux_amd64_sysv.r12], r12
        mov [rdi+fiber_t_linux_amd64_sysv.r13], r13
        mov [rdi+fiber_t_linux_amd64_sysv.r14], r14
        mov [rdi+fiber_t_linux_amd64_sysv.r15], r15

        mov r8, [rsi+fiber_t_linux_amd64_sysv.ret]
        mov rsp, [rsi+fiber_t_linux_amd64_sysv.rsp]
        mov rbx, [rsi+fiber_t_linux_amd64_sysv.rbx]
        mov rbp, [rsi+fiber_t_linux_amd64_sysv.rbp]
        mov r12, [rsi+fiber_t_linux_amd64_sysv.r12]
        mov r13, [rsi+fiber_t_linux_amd64_sysv.r13]
        mov r14, [rsi+fiber_t_linux_amd64_sysv.r14]
        mov r15, [rsi+fiber_t_linux_amd64_sysv.r15]
        jmp r8
    %else
        %error "Unsupported target ABI"
    %endif
    hlt