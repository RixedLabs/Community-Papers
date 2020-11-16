.code

main:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rax, [count]
    inc qword ptr [count]
    cmp rax, 3
    jge bye
    xor ecx, ecx
    call next
    db "Hello World!", 0

next:
    pop rdx
    call fuck
    db "x0r19x91", 0

fuck:
    pop r8
    mov r9d, 040h
    mov rax, [fnMessageBoxA]
    call rax

bye:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

   count dq 0
   fnMessageBoxA dq 00007FF9D30B2CE0h

end
