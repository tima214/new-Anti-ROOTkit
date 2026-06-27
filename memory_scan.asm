BITS 64

section .data
    msg_title db "=== ASM: Memory Scan ===", 13, 10, 0
    msg_pid db "  Process: ", 0
    msg_regions db " | Regions: ", 0
    msg_newline db 13, 10, 0
    msg_error db "[-] ASM: Failed to scan memory", 13, 10, 0
    msg_footer db "=== ASM: Scan Complete ===", 13, 10, 0
    
    PAGE_EXECUTE_READWRITE equ 0x40
    MEM_COMMIT equ 0x1000


section .bss
    processes resq 1024
    mbi resb 48

section .text
    global asm_memory_scan
    extern printf
    extern EnumProcesses
    extern OpenProcess
    extern VirtualQueryEx
    extern CloseHandle

asm_memory_scan:
    push rbp
    mov rbp, rsp
    sub rsp, 64
    
    lea rcx, [msg_title]
    call printf
    
    lea rcx, [processes]
    mov rdx, 4096
    lea r8, [rsp + 32]
    call EnumProcesses
    
    test rax, rax
    jz .error
    
    mov r10, [rsp + 32]
    shr r10, 2
    xor r11, r11
    
.scan_loop:
    cmp r11, r10
    jge .done
    
    mov eax, [processes + r11 * 4]
    test eax, eax
    jz .next
    
    mov rcx, 0x0410
    mov rdx, rax
    xor r8, r8
    call OpenProcess
    
    test rax, rax
    jz .next

    
    push rax
    xor rdx, rdx
    lea r8, [mbi]
    mov r9, 48
    xor rbx, rbx
    
.scan_mem:
    call VirtualQueryEx
    test rax, rax
    jz .close_proc
    
    mov eax, [mbi + 16]
    and eax, MEM_COMMIT
    jz .next_region
    
    mov eax, [mbi + 20]
    and eax, PAGE_EXECUTE_READWRITE
    jz .next_region
    
    inc rbx
    
.next_region:
    mov rax, [mbi]
    add rax, [mbi + 8]
    mov rdx, rax
    lea r8, [mbi]
    mov r9, 48
    jmp .scan_mem
    
.close_proc:
    pop rcx
    call CloseHandle
    
    test rbx, rbx
    jz .next
    
    lea rcx, [msg_pid]
    call printf
    
    mov eax, [processes + r11 * 4]
    mov [rsp + 40], eax
    mov rcx, [rsp + 40]
    call print_num
    
    lea rcx, [msg_regions]
    call printf
    
    mov rcx, rbx
    call print_num
    
    lea rcx, [msg_newline]
    call printf

.next:
    inc r11
    jmp .scan_loop

.error:
    lea rcx, [msg_error]
    call printf

.done:
    lea rcx, [msg_newline]
    call printf
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