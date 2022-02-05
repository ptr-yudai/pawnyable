global _start
section .text
_start:
  xor edx, edx
  push rdx
  lea rdi, [rel s_arg2]
  push rdi
  lea rdi, [rel s_arg1]
  push rdi
  lea rdi, [rel s_arg0]
  push rdi
  mov rsi, rsp
  mov eax, 59
  syscall
  int3

s_arg0: db "/bin/sh", 0
s_arg1: db "-c", 0
s_arg2: db "/bin/ls -lha", 0
