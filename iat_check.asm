BITS 64

section .data
    msg_title db "=== ASM: IAT Check ===", 13, 10, 0
    msg_hook db "  Hook in ", 0
    msg_count db " | Count: ", 0
    msg_newline db 13, 10, 0
    msg_error db "[-] ASM: Failed to check IAT", 13, 10, 0
    msg_footer db "=== ASM: Check Complete ===", 13, 10, 0
    
    IMAGE_ORDINAL_FLAG equ 0x80000000

section .bss
    modules resq 1024
    module_name resb 260

section .text
    global asm_iat_check
    extern printf
    extern EnumProcessModules
    extern GetModuleFileNameExA
    extern GetCurrentProcess

asm_iat_check:
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
    xor r12, r12
    
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
    cmp dx, 0x5A4D
    jne .next_module
    
    mov rdx, [rax + 0x3C]
    add rdx, rax
    cmp dword [rdx], 0x00004550
    jne .next_module
    
    mov rdx, [rdx + 0x90]
    test rdx, rdx
    jz .next_module
    
    add rdx, rax
    xor rbx, rbx
    
.check_imports:
    cmp dword [rdx], 0
    je .next_module
    
    mov r8, [rdx + 16]
    add r8, rax
    
    mov r9, [rdx]
    add r9, rax
    
    xor r10, r10
    
.check_thunk:
    mov r11, [r9 + r10 * 8]
    test r11, r11
    jz .next_import
    
    mov r12, [r8 + r10 * 8]
    
    test r11, IMAGE_ORDINAL_FLAG
    jnz .check_addr
    
    mov r11, r11
    add r11, 2
    add r11, rax
    
.check_addr:
    mov r13, [r8 + r10 * 8]
    
    pop r14
    push r14
    mov r14, [r14 + 0x3C]
    add r14, rax
    mov r14, [r14 + 0x50]
    
    cmp r13, rax
    jb .found_hook
    
    add rax, r14
    cmp r13, rax
    ja .found_hook
    sub rax, r14
    
    jmp .next_thunk
    
.found_hook:
    inc r15
    inc r12
    
.next_thunk:
    inc r10
    jmp .check_thunk
    
.next_import:
    add rdx, 20
    jmp .check_imports
    
.next_module:
    pop rax
    inc r11
    jmp .scan_loop

.error:
    lea rcx, [msg_error]
    call printf
    jmp .done

.done:
    lea rcx, [msg_footer]
    call printf
    
    mov rsp, rbp
    pop rbp
    ret