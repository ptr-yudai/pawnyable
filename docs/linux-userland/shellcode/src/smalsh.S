global _start
section .text

_start:
  mov rax, 0xdeadbeefcafebabe
  mov rbx, 0xdeadbeefcafebabe
  mov rcx, 0xdeadbeefcafebabe
  mov rdx, 0xdeadbeefcafebabe
  mov rsi, 0xdeadbeefcafebabe
  mov rdi, 0xdeadbeefcafebabe
  mov rsp, 0xdeadbeefcafebabe
  mov rbp, 0xdeadbeefcafebabe
  mov r8, 0xdeadbeefcafebabe
  mov r9, 0xdeadbeefcafebabe
  mov r10, 0xdeadbeefcafebabe
  mov r11, 0xdeadbeefcafebabe
  mov r12, 0xdeadbeefcafebabe
  mov r13, 0xdeadbeefcafebabe
  mov r14, 0xdeadbeefcafebabe
  mov r15, 0xdeadbeefcafebabe

  syscall
  xor eax, eax
  cdq
  mov esi, eax
  lea rdi, [rcx+13]
  mov al, 59
  syscall
  db "/bin/sh",0
