---
title: "Holstein v3: Use-after-Freeの悪用"
tags:
    - [Linux]
    - [Kernel]
    - [Use-after-Free]
    - [kROP]
    - [stack pivot]
    - [AAR]
    - [AAW]
    - [cred]
lang: ja
---
前章ではHolsteinモジュールのHeap Overflowを悪用して権限昇格をしました。またもやHolsteinモジュールの開発者は脆弱性を修正し、Holstein v3を公開しました。本章では、改善されたHolsteinモジュールv3をexploitしていきます。

<div class="column" title="目次">
<!-- toc --><br>
</div>

## パッチの解析と脆弱性の調査
まずは[Holstein v3](distfiles/LK01-3.tar.gz)をダウンロードしてください。


