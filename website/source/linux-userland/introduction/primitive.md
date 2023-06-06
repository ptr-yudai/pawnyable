---
title: Primitiveについて
date: 2022-02-07 23:11:00
tags:
    - [Linux]
    - [Userland]
    - [AAR]
    - [AAW]
lang: ja

pagination: true
bk: security.html
fd: environment.html
---
Binary Exploitationにおいて最も重要となるのがprimitiveと呼ばれるものです。本章では、primitiveの種類と重要性について説明します。

## Primitiveとは
Binary Exploitationとは、脆弱性を利用して目的を達成する作業です。
例えば「整数オーバーフローで値が負になる」という脆弱性から「任意コード実行する」という目的に向けてexploitを記述します。この過程で重要になってくるのが**primitive**（プリミティブ：原理）です。Primitiveとは、あらゆるexploitにおいて役に立つ基本的な処理のことです。いわば、脆弱性と目的を橋渡しする中間にあるプロセスを指します。
例えば「任意のアドレスからデータを読める」や「RIPを自由に制御できる」といった処理が一般的なprimitiveにあたります。Exploitの対象や攻撃手法によってprimitiveは異なりますが、綺麗なexploitを書くためには必ずprimitiveを作ることを意識しましょう。特に、何度でも呼び出せるPrimitiveを作っておくことで、exploitを後から容易に変更できたり、exploit自体が安定化したりといったメリットがあります。

## 一般的なprimitive
Exploitにより何をprimitiveと呼ぶかは様々ですが、ここでは多くのexploitで共通して使われるprimitiveを挙げます。

### RIP制御
Exploitにおいて最も重要となるprimitiveがRIP制御です。リターンアドレスや関数ポインタを書き換えて任意のアドレスにジャンプすることを指します。
もちろんコマンドインジェクションなどの脆弱性の場合は不要ですが、多くのexploitでは必要となります。多くのRIP制御は1回だけ使いますが、[ROP](../stack/rop.html)の章でも説明するように何度もRIP制御を使う特殊なパターンも存在します。

### アドレスリーク
近年の多くのアーキテクチャではASLRが有効です。ASLRを安定して回避するためにはライブラリやプログラム、ヒープなどのアドレスをリークする必要になります。何かしらの方法でアドレスをリークするprimitiveを**アドレスリーク**と呼びます。未初期化のメモリを使ったり、Type Confusionでポインタと整数値を混同させたり、アドレスリークの手法は脆弱性によって様々です。

<div class="balloon_l">
  <div class="faceicon"><img src="../img/piyo_yaba.png" alt="ひよこ先生" ></div>
  <p class="says">
    アドレスリークと似た言葉に<b>メモリリーク</b>という言葉があるよ。メモリの内容がリークしそうな言葉だけど、メモリリークは確保したメモリを解放(free)し忘れてメモリを消費し続けるバグを指しているから注意してね。
  </p>
</div>

### addrof
特にJavaScript Exploitでは、変数（JavaScriptオブジェクト）のアドレスをリークします。このように特定のオブジェクトのアドレスをリークするprimitiveを**addrof**(address of)と呼びます。つまり、addrofはオブジェクトを渡すとアドレスがリークできる関数です。
```
addr_obj = addrof(obj)
```

### fakeobj
addrofと逆に、アドレスを渡すとそのメモリ領域を何かしらのオブジェクトとして認識させるprimitiveを**fakeobj**と呼びます。例えばヒープ関連のexploit経験のある方なら、脆弱性を利用して`malloc`関数に任意のアドレスを返させたことがあるでしょう。これは特定のアドレスにオブジェクトを作ったことになります。
```
obj = fakeobj(addr_obj)
```
fakeobjとaddrofは常に次の関係にあります。
```
obj = fakeobj(addrof(obj))
addr = addrof(fakeobj(addr))
```
このprimitiveについては意識して作ることは少ないでしょうが、JavaScript Exploitなどでは頻出のprimitiveですので、頭の片隅に記憶しておいてください。

### AAR
任意のアドレスからデータを読むprimitiveを**AAR**(Arbitrary Address Read)などと呼びます。このprimitiveはアドレスリークなどに役立ちます。
AAR primitiveを持っていると、例えばlibcからスタックのアドレスをリークし、さらにスタックのアドレスからプログラムのベースアドレスをリークする、といったアドレスチェインを辿ることができます。

### AAW
任意のアドレスにデータを書き込むprimitiveを**AAW**(Arbitrary Address Write)や**WWW**(Write-What-Where)などと呼びます。このprimitiveは関数ポインタの書き換え（RIP制御）などに役立ちます。
特にKernel Exploitにおいては、安定した[^1]AARとAAWが実現できれば権限昇格が可能です。AAR, AAWは非常に強力なprimitiveなので、脆弱性を使って実現できるかを考えるようにしましょう。

[^1]: カーネル空間では`copy_to_user`や`copy_from_user`といった関数を使うとマップされていない不正なアドレスでもクラッシュせずデータの読み書きを試行できる。

----

<div class="column" title="例題">
  次のFSBを何度も呼び出せるとき、アドレスリーク、AAR、AAWの3つのprimitiveはどのように作れるでしょうか。FORTIFYは無効とします。
  <pre>
  char buf[0x100] = {};
  read(0, buf, 0x100);
  printf(buf);</pre>
</div>
