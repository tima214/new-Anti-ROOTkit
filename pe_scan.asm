BITS 64

section .data
    msg_title db "=== ASM: PE Scan ===", 13, 10, 0
    msg_module db "  Module: ", 0
    msg_rwx db " | RWX: ", 0
    msg_newline db 13, 10, 0
    msg_error db "[-] ASM: Failed to scan PE", 13, 10, 0
    msg_footer db "=== ASM: Scan Complete ===", 13, 10, 0
    msg_name db " | Name: ", 0
    
    IMAGE_DOS_SIGNATURE equ 0x5A4D
    IMAGE_NT_SIGNATURE equ 0x00004550
    IMAGE_SCN_MEM_EXECUTE equ 0x20000000
    IMAGE_SCN_MEM_WRITE equ 0x80000000

section .bss
    modules resq 1024
    module_name resb 260

section .text
    global asm_pe_scan
    extern printf
    extern EnumProcessModules
    extern GetModuleFileNameExA
    extern GetCurrentProcess

asm_pe_scan:
    push rbp
    mov rbp, rsp
    sub rsp, 64
    
    lea rcx, [msg_title]
    call printf
    
    call GetCurrentProcess
    
    lea rdx, [modules]
    mov rcx, rax
    mov r8, 8192
    lea r9, [rsp + 32]
    call EnumProcessModules
    
    test rax, rax
    jz .error
    
    mov r10, [rsp + 32]
    shr r10, 3
    xor r11, r11
    
.scan_loop:
    cmp r11, r10
    jge .done
    
    mov rax, [modules + r11 * 8]
    test rax, rax
    jz .next
    
    push rax
    
    call GetCurrentProcess
    pop rdx
    push rdx
    
    lea r8, [module_name]
    mov r9, 260
    mov rcx, rax
    call GetModuleFileNameExA
    
    pop rcx
    push rcx
    
    mov rax, rcx
    movzx rdx, word [rax]
    cmp dx, IMAGE_DOS_SIGNATURE
    jne .next_module
    
    mov rdx, [rax + 0x3C]
    add rdx, rax
    cmp dword [rdx], IMAGE_NT_SIGNATURE
    jne .next_module
    
    lea rcx, [msg_module]
    call printf
    
    lea rcx, [module_name]
    call get_name
    call printf
    
    mov rdx, [rax + 0x3C]
    add rdx, rax
    add rdx, 0x18
    movzx rcx, word [rdx + 16]
    mov rdx, [rax + 0x3C]
    add rdx, rax
    add rdx, 0x18
    add rdx, 0x20
    add rdx, [rdx + 0x10]
    add rdx, 0x18
    
    xor r8, r8
    xor r9, r9
    
.section_loop:
    cmp r8, rcx
    jge .print_rwx
    
    mov eax, [rdx + 36]
    and eax, IMAGE_SCN_MEM_EXECUTE
    jz .next_section
    
    mov eax, [rdx + 36]
    and eax, IMAGE_SCN_MEM_WRITE
    jz .next_section
    
    inc r9
    
.next_section:
    add rdx, 40
    inc r8
    jmp .section_loop
    
.print_rwx:
    pop rax
    lea rcx, [msg_rwx]
    call printf
    
    mov rcx, r9
    call print_num
    
    lea rcx, [msg_newline]
    call printf
    jmp .next

.next_module:
    pop rax

.next:
    inc r11
    jmp .scan_loop

.error:
    lea rcx, [msg_error]
    call printf

.done:
    lea rcx, [msg_footer]
    call printf
    
    mov rsp, rbp
    pop rbp
    ret

get_name:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rax, rcx
    mov rdx, rcx
    
.find:
    cmp byte [rax], 0
    je .found
    cmp byte [rax], '\\'
    je .found_slash
    inc rax
    jmp .find
    
.found_slash:
    inc rax
    mov rdx, rax
    jmp .find
    
.found:
    mov rax, rdx
    
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