---
title: FUSEの利用
tags:
    - [Linux]
    - [Kernel]
    - [Race Condition]
    - [Data Race]
    - [FUSE]
lang: ja
---
[前章](uffd.html)ではuserfaultfdを利用してLK04(Fleckvieh)の競合を安定化させました。本章では同じくLK04を、別の方法でexploitしてみます。

<div class="column" title="目次">
<!-- toc --><br>
</div>

## userfaultfdの欠点
前章でも少し説明したように、userfaultfdは現在のLinuxでは標準で一般ユーザーは利用できません。正確には、ユーザー空間で発生さしたページフォルトは検知できますが、カーネル空間で発生したものは一般ユーザーの作ったuserfaultfdでは検知できません。それぞれ以下のパッチで導入されたセキュリティ緩和機構です。

- [userfaultfd: allow to forbid unprivileged users](https://lwn.net/Articles/782745/)
- [Control over userfaultfd kernel-fault handling](https://lwn.net/Articles/835373/)

そこで、今回はLinuxの機能の一つであるFUSEという仕組みを利用します。まずはFUSEとは何かを勉強しましょう。

## FUSEとは
[**FUSE**(Filesystem in Userspace)](https://lwn.net/Articles/68104/)は、ユーザー空間から仮想的にファイルシステムの実装を可能にするLinuxの機能です。`CONFIG_FUSE_FS`を付けてカーネルをビルドすると有効になります。
まず、プログラムはFUSEを使ってファイルシステムをマウントします。誰かがこのファイルシステム中のファイルにアクセスすると、プログラム側で設定したハンドラが呼び出されます。構造はLK01で見たキャラクターデバイスの実装と非常に似ています[^1]。


## FUSEの利用
システム上のFUSEのバージョンは`fusermount`コマンドで調査できます。
```
/ $ fusermount -V
fusermount version: 2.9.9
```

<center>
  <img src="img/uffd_sample.png" alt="userfaultfdの使用例" style="width:480px;">
</center>

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="オオカミくん" ></div>
  <p class="says">
    userfaultfdのハンドラは別スレッドで動くから、メインスレッドと違うCPUで動く可能性があるよ。
    ハンドラ内でオブジェクトを確保するとき、CPUごとにキャッシュされたヒープ領域が使われるとUAFが失敗しちゃうから、sched_setaffinity関数でCPUを固定するように注意してね。
  </p>
</div>

---

[^1]: ユーザー空間で仮想的にキャラクタデバイスを登録するCUSEという仕組みもあります。
[^2]: 
