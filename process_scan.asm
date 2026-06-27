BITS 64

section .data
    msg_title db "=== ASM: Process Scan ===", 13, 10, 0
    msg_pid db "  PID: ", 0
    msg_name db " | Name: ", 0
    msg_newline db 13, 10, 0
    msg_error db "[-] ASM: Failed to create snapshot", 13, 10, 0
    msg_footer db "=== ASM: Scan Complete ===", 13, 10, 0
    
    TH32CS_SNAPPROCESS equ 0x00000002
    INVALID_HANDLE_VALUE equ -1

section .bss
    snapshot resq 1
    pe32 resb 1024
    temp resd 1

section .text
    global asm_process_scan
    extern printf
    extern CreateToolhelp32Snapshot
    extern Process32First
    extern Process32Next
    extern CloseHandle

asm_process_scan:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    lea rcx, [msg_title]
    call printf
    
    mov rcx, TH32CS_SNAPPROCESS
    xor rdx, rdx
    call CreateToolhelp32Snapshot
    
    cmp rax, INVALID_HANDLE_VALUE
    je .error
    
    mov [snapshot], rax
    
    mov rcx, rax
    lea rdx, [pe32]
    mov dword [rdx], 1024
    call Process32First
    
    test rax, rax
    jz .close
    
.loop:
    lea rcx, [msg_pid]
    call printf
    
    mov eax, [pe32]
    mov [temp], eax
    mov rcx, [temp]
    call print_num
    
    lea rcx, [msg_name]
    call printf
    
    lea rcx, [pe32 + 8]
    call printf
    
    lea rcx, [msg_newline]
    call printf
    
    mov rcx, [snapshot]
    lea rdx, [pe32]
    call Process32Next
    
    test rax, rax
    jnz .loop

.close:
    mov rcx, [snapshot]
    call CloseHandle
    jmp .done

.error:
    lea rcx, [msg_error]
    call printf

.done:
    lea rcx, [msg_footer]
    call printf
    
    mov rsp, rbp
    pop rbp
    ret

print_num:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rax, rcx
    mov rbx, 10
    xor rcx, rcx
    xor rdx, rdx
    
.loop:
    xor rdx, rdx
    div rbx
    push rdx
    inc rcx
    test rax, rax
    jnz .loop
    
.print:
    pop rax
    add rax, '0'
    mov [rsp + 16], rax
    mov byte [rsp + 17], 0
    lea rcx, [rsp + 16]
    call printf
    dec rcx
    test rcx, rcx
    jnz .print
    
    mov rsp, rbp
    pop rbp
    ret