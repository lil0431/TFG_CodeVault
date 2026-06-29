.section .data
    msg_welcome:    .asciz "Welcome to the system\n"
    msg_prompt:     .asciz "Enter password: "
    msg_success:    .asciz "Access granted!\n"
    msg_failure:    .asciz "Access denied!\n"
    msg_admin:      .asciz "admin"
    buffer:         .space 64

.section .text
    .globl main
    .globl read_input
    .globl check_password
    .globl print_message
    .globl process_input

main:
    push %rbp
    mov %rsp, %rbp
    sub $16, %rsp
    
    lea msg_welcome(%rip), %rdi
    call print_message
    
    lea msg_prompt(%rip), %rdi
    call print_message
    
    lea buffer(%rip), %rdi
    mov $64, %rsi
    call read_input
    
    lea buffer(%rip), %rdi
    call process_input
    
    mov $0, %rax
    mov %rbp, %rsp
    pop %rbp
    ret

read_input:
    push %rbp
    mov %rsp, %rbp
    
    mov $0, %rax
    mov $0, %rdi
    mov %rdi, %rsi
    mov %rdx, %rdx
    syscall
    
    mov %rbp, %rsp
    pop %rbp
    ret

process_input:
    push %rbp
    mov %rsp, %rbp
    sub $16, %rsp
    
    mov %rdi, -8(%rbp)
    
    lea -8(%rbp), %rsi
    lea msg_admin(%rip), %rdi
    call check_password
    
    cmp $1, %rax
    jne .access_denied
    
    lea msg_success(%rip), %rdi
    call print_message
    jmp .done_process
    
.access_denied:
    lea msg_failure(%rip), %rdi
    call print_message
    
.done_process:
    mov %rbp, %rsp
    pop %rbp
    ret

check_password:
    push %rbp
    mov %rsp, %rbp
    sub $32, %rsp
    
    mov %rdi, -8(%rbp)
    mov %rsi, -16(%rbp)
    
    xor %rcx, %rcx
    
.loop_cmp:
    cmp $32, %rcx
    jge .cmp_done
    
    mov -8(%rbp), %rax
    mov -16(%rbp), %rbx
    
    mov (%rax, %rcx), %al
    mov (%rbx, %rcx), %bl
    
    cmp %al, %bl
    jne .cmp_mismatch
    
    cmp $0, %al
    je .cmp_match
    
    inc %rcx
    jmp .loop_cmp
    
.cmp_match:
    mov $1, %rax
    jmp .cmp_done
    
.cmp_mismatch:
    mov $0, %rax
    
.cmp_done:
    mov %rbp, %rsp
    pop %rbp
    ret

print_message:
    push %rbp
    mov %rsp, %rbp
    
    mov %rdi, %rsi
    xor %rcx, %rcx
    
.count_loop:
    mov (%rsi, %rcx), %al
    cmp $0, %al
    je .count_done
    inc %rcx
    jmp .count_loop
    
.count_done:
    mov $1, %rax
    mov $1, %rdi
    mov %rsi, %rsi
    mov %rcx, %rdx
    syscall
    
    mov %rbp, %rsp
    pop %rbp
    ret