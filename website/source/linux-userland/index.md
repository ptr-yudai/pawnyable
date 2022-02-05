---
title: Linux Userland Exploitation
---
この章では🐤ひよこ先生と一緒にLinuxのユーザー空間におけるExploit手法について学びます。Linuxのユーザー空間におけるExploit手法を解説した資料は人間社会にも多数出回っているため、ここではより重要な知識のみを説明します。

- シェルコード
  - [シェルコードの書き方](shellcode/how2write.html)
  - [制約付きシェルコード](shellcode/restricted.html)
  - [seccompの回避](shellcode/seccomp.html)
  - [Egg Hunter](shellcode/egg-hunter.html)
  - [Bring Your Own Gadget](shellcode/byog.html)
- LK01: Holstein
  - [Holsteinモジュールの解析と脆弱性の発火](LK01/welcome-to-holstein.html)
  - [Holstein v1: Stack Overflowの悪用](LK01/stack_overflow.html)
  - [Holstein v2: Heap Overflowの悪用 (工事中)](LK01/heap_overflow.html)
  - [Holstein v3: Use-after-Freeの悪用 (工事中)](LK01/use_after_free.html)
- カーネル特有の攻撃手法
  - [NULL Pointer Dereference (LK0?: Angus) (工事中)](#)
  - [ユーザー空間のポインタの利用 (LK0?: Highland) (工事中)](#)
  - [Double Fetch (LK0?: Dexter) (工事中)](#)
  - [Race Conditionとuserfaultfd (LK0?: Hereford) (工事中)](#)
  - [BPFとJIT (LK0?: Brahman) (工事中)](#)
- その他の脆弱性
  - [参照カウンタ (LK0?: Simmental) (工事中)](#)
  - [サイドチャネル攻撃 (LK0?: Charolai) (工事中)](#)
- UEFIに対する攻撃
  - UEFIアプリケーションの特徴
  - メモリアロケータ
