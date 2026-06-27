BITS 64

section .

.done:

msg_footer db "=== ASM: driver Scan Complete ===", 13, 10, 0
msg_error db "[-] ASM: Failed to scan driver", 13, 10, 0

push rbp
	mov rsp, rbp
	pop rbp
	ret

	mov rcx, [msg_footer]
	mov rdx, 0
	call printf

	mov rcx, [msg_error]
	mov rdx, 0
	call printf
