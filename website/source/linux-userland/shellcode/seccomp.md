---
title: seccompの回避
date: 2022-02-05 12:43:00
tags:
    - [Linux]
    - [Userland]
    - [shellcode]
    - [seccomp]
lang: ja
---
Linuxではseccompと呼ばれるサンドボックス機構が提供されています。seccompは正しく使えば非常に強力ですが、フィルタの設定を誤ると簡単に回避できてしまいます。この章ではseccompの様々な回避手法について紹介します。

<div class="column" title="目次">
<!-- toc --><br>
</div>

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
すると、次のように強制終了します。
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

### openatとexecveat
まず典型的なミスは、`execve`や`open`だけ禁止して、`execveat`や`openat`などの同等の機能を備えたマイナーなシステムコールを禁止し忘れるパターンです。



### creatとprocfs


### ptrace





### process\_vm\_readv, process\_vm\_writev


### open\_by\_handle\_at, name\_to\_handle\_at


## サイドチャネル攻撃
メモリ上の情報漏洩が目的で、コマンド実行などが不要な場合もあります。このような場合はシステムコールを利用せずに情報漏洩が可能かもしれません。

### エラーの観測


### 処理時間の計測


## その他の回避手法


### 他プロセスの悪用

#### kill, tkill, tgkill


#### prlimit64



### カーネルやライブラリの欠陥の利用

