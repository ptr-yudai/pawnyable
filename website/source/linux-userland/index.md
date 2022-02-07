---
title: Linux Userland Exploitation
---
この章ではひよこ先生🐤と一緒にLinuxのユーザー空間におけるExploit手法について学びます。Linuxのユーザー空間におけるExploit手法を解説した資料は人間社会にも多数出回っているため、ここではより重要な知識のみを説明します。

- 前提知識
  - [セキュリティ機構](introduction/security.html)
  - [Primitiveについて](introduction/primitive.html)
- シェルコード
  - [シェルコードの書き方](shellcode/how2write.html)
  - [制約付きシェルコード](shellcode/restricted.html)
  - [seccompの回避（工事中）](shellcode/seccomp.html)
  - [Egg Hunter（工事中）](shellcode/egg-hunter.html)
  - [Bring Your Own Gadget（工事中）](shellcode/byog.html)
- スタック
  - [Stack Buffer Overflow](stack/bof.html)
  - [Return Oriented Programming](stack/rop.html)
  - [forkとcanary](stack/fork.html)
  - [スレッドとcanary](stack/thread.html)
- ヒープ
  - [Call/Jump Oriented Programming](heap/cop.html)
  - [Heap Buffer Overflow](heap/bof.html)
  - [Use-after-Free](heap/uaf.html)
  - [Heap Sprayその１：特定のアドレスにデータを置く手法](heap/spray1.html)
  - [Heap Sprayその２：2つのオブジェクトを隣接させる手法](heap/spray2.html)
  - [Heap Sprayその３：ヒープの初期状態を固定する手法](heap/spray3.html)
- その他の脆弱性
  - [Format String Bug](others/fsb.html)
  - [Integer Overflow](others/integer.html)
  - [Type Confusion](others/confusion.html)

<div class="column" title="豆知識：ひよこ鑑定士">
  　鶏の雛はオスとメスがそれぞれ半分ずつ程度の割合で生まれますが、とくに卵を生産する採卵農場ではメスの鶏が必要になります。食肉専用のブロイラーでも性別によって異なる場所で飼育されることがありますが、その性別の判定は非常に難しいとされています。<br>
  　これを判別する職業として初生雛鑑別師（通称：<b>ひよこ鑑定士</b>）と呼ばれる職業があります。日本では民間資格が存在し、養成所を修了するなどの条件を満たした人だけが受験できます。しかし、この試験に合格しただけでは職業鑑別師としては働けず、さらに数年間の研修を経て経験を積む必要があります。<br>
  　ひよこ鑑定士は「ひよこかそれ以外の物体か」を判別する職業ではないので、使い方を間違えないように注意しましょう。
</div>
