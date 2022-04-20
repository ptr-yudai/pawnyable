---
title: Linux Kernel Exploitation
---

<div class="balloon_l">
  <div class="faceicon"><img src="img/wolf_normal.smal.png" alt="オオカミくん" ></div>
  <p class="says">
  この章を担当するオオカミです。この章ではカーネル空間におけるExploit手法、いわゆる権限昇格について勉強していきましょう。<br>
  WindowsのKernel Exploitでも共通のハードウェアセキュリティ機構や権限昇格の手法が登場するから、この章の知識はLinuxに限らず使えるよ。
  </p>
</div>

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
- カーネル空間特有の攻撃
  - [NULL Pointer Dereference (LK02: Angus)](LK02/null_ptr_deref.html)
  - [Double Fetch (LK03: Dexter)](LK03/double_fetch.html)
  - [userfaultfdとFUSEの利用 (LK04: Fleckvieh) (工事中)](LK04/uffd_and_fuse.html)
  - [脆弱なmmap実装の悪用 (LK0?: Highland) (工事中)](#)
  - [eBPFとJIT (LK0?: Brahman) (工事中)](#)
- その他の脆弱性
  - [参照カウンタ (LK0?: Simmental) (工事中)](#)
  - [サイドチャネル攻撃 (LK0?: Charolai) (工事中)](#)
