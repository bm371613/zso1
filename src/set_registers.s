    .global set_registers

    .text
set_registers:
    push (eflags)
    popf
    mov (eax), %eax
    mov (ebx), %ebx
    mov (ecx), %ecx
    mov (edx), %edx
    mov (esi), %esi
    mov (edi), %edi
    mov (ebp), %ebp
    mov (esp), %esp
    push (eip)
    ret
