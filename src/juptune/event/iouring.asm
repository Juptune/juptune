[section .text]

; Opcodes are taken from
; https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls

global io_uring_setup
global io_uring_enter
global io_uring_register

io_uring_setup:
    %ifdef linux_amd64_sysv
        mov rax, 425
        syscall
    %else
        %error "Unsupported target ABI"
    %endif
    ret

io_uring_enter:
    %ifdef linux_amd64_sysv
        mov rax, 426
        mov r10, rcx
        mov r9, r8
        syscall
    %else
        %error "Unsupported target ABI"
    %endif
    ret

io_uring_register:
    %ifdef linux_amd64_sysv
        mov rax, 427
        mov r10, rcx
        syscall
    %else
        %error "Unsupported target ABI"
    %endif
    ret