---
title: Linux Kernel Exploitation
---
この章では~~牛さん🐮~~yoshi-campなのでyoshikingと一緒にLinuxのカーネル空間におけるExploit手法、すなわち権限昇格について学びます。WindowsのKernel Exploitでも共通のハードウェアセキュリティ機構や権限昇格の手法に関する説明も含まれています。

- 実行環境とデバッグ方法
  - [Kernel Exploitへの導入](introduction/introduction.html)
  - [gdbによるカーネルのデバッグ](introduction/debugging.html)
  - [セキュリティ機構](introduction/security.html)
  - [コンパイルとexploitの転送](introduction/compile-and-transfer.html)
- カーネルエクスプロイトの基礎（LK01: Holstein）
  - [Holsteinモジュールの解析と脆弱性の発火](LK01/welcome-to-holstein.html)
  - [Holstein v1: Stack Overflowの悪用](LK01/stack_overflow.html)
  - [Holstein v2: Heap Overflowの悪用](LK01/heap_overflow.html)
  - [Holstein v3: Use-after-Freeの悪用](LK01/use_after_free.html)
  - [Holstein v4: Race Conditionの悪用](LK01/race_condition.html)
- カーネル特有の攻撃手法
  - [NULL Pointer Dereference (LK02: Angus)](LK02/null_ptr_deref.html)
  - [ユーザー空間のポインタの利用 (LK0?: Highland) (工事中)](#)
  - [Double Fetch (LK0?: Dexter) (工事中)](#)
  - [脆弱なmmap実装の悪用 (LK0?: ?) (工事中)](#)
  - [eBPFとJIT (LK0?: Brahman) (工事中)](#)
- その他の脆弱性
  - [参照カウンタ (LK0?: Simmental) (工事中)](#)
  - [サイドチャネル攻撃 (LK0?: Charolai) (工事中)](#)
- UEFIに対する攻撃
  - UEFIアプリケーションの特徴
  - メモリアロケータ
