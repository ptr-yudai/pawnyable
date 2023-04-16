---
title: セキュリティ機構
date: 2023-04-16 19:20:00
tags:
    - [Linux]
    - [Userland]
lang: ja
---
この章では、Linuxのユーザー空間で登場するセキュリティ機構や、それにまつわる用語について説明します。

<div class="column" title="目次">
<!-- toc --><br>
</div>

## OSやCPUレベルのセキュリティ機構

セキュリティ機構には、大きくわけてOS/CPUレベルのものと、コンパイラ/プログラムレベルのものの2種類があります。
ユーザー空間のプログラムを攻撃する際、一般にOS/CPUレベルのセキュリティ機構はコンパイラ/プログラムレベルのものより強力です。
一般的にOS/CPUレベルのセキュリティ機構は、脆弱性を利用して無力化することができても、無効化することはできません。

まずはOS/CPUレベルのセキュリティ機構から見ていきましょう。

### ASLR

ASLR (Address Space Layout Randomization)は、特定のメモリ領域がマップされるアドレスを、プログラム起動時にランダムに設定するセキュリティ機構です。
アドレスをランダム化することで攻撃者はアドレスがわからなくなるため、特定の場所にあるデータ構造を破壊したり利用したりできなくなります。

ASLRはOSのプログラムローダに搭載されたセキュリティ機構です。
乱数を利用するコードは[randomize_page関数](https://elixir.bootlin.com/linux/latest/source/mm/util.c#L329)に記載されています。
ローダは[load_elf_binary関数](https://elixir.bootlin.com/linux/latest/source/fs/binfmt_elf.c#L818)で定義されています。

```c
static int load_elf_binary(struct linux_binprm *bprm)
{
    ...
    // [1]
	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		current->flags |= PF_RANDOMIZE;
    ...
    // [2]
	retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
				 executable_stack);
    ...
    // [3]
	if ((current->flags & PF_RANDOMIZE) && (randomize_va_space > 1)) {
		/*
		 * For architectures with ELF randomization, when executing
		 * a loader directly (i.e. no interpreter listed in ELF
		 * headers), move the brk area out of the mmap region
		 * (since it grows up, and may collide early with the stack
		 * growing down), and into the unused ELF_ET_DYN_BASE region.
		 */
		if (IS_ENABLED(CONFIG_ARCH_HAS_ELF_RANDOMIZE) &&
		    elf_ex->e_type == ET_DYN && !interpreter) {
			mm->brk = mm->start_brk = ELF_ET_DYN_BASE;
		}

		mm->brk = mm->start_brk = arch_randomize_brk(mm);
#ifdef compat_brk_randomized
		current->brk_randomized = 1;
#endif
	}
```

まず、\[1\]で`current->personality`と`randomize_va_space`を確認して`PF_RANDOMIZE`フラグを設定しています。
`current->personality`は、`personality`システムコールで設定できるプロセス固有のパラメータで、通常`ADDR_NO_RANDOMIZE`は付いていません。
`randomize_va_space`は、`/proc/sys/kernel/randomize_va_space`経由でユーザー空間から設定できるカーネル共通のパラメータで、コードから分かるように0に設定するとASLRが無効化できます。

さて、\[2\]でスタックをマップしています。
第２引数にスタック領域の先頭（スタックボトム）のアドレスが渡されますが、ここで[`randomize_stack_top`](https://elixir.bootlin.com/linux/latest/source/mm/util.c#L299)が使われています。
```c
unsigned long randomize_stack_top(unsigned long stack_top)
{
	unsigned long random_variable = 0;

	if (current->flags & PF_RANDOMIZE) {
		random_variable = get_random_long();
		random_variable &= STACK_RND_MASK;
		random_variable <<= PAGE_SHIFT;
	}
#ifdef CONFIG_STACK_GROWSUP
	return PAGE_ALIGN(stack_top) + random_variable;
#else
	return PAGE_ALIGN(stack_top) - random_variable;
#endif
}
```
`STACK_RND_MASK`は32-bitでは0x7ff, 64-bitでは0x3fffffと定義されています。
したがって、スタックのアドレスがランダム化されます。

続いて[`arch_randomize_brk`](https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/process.c#L972)は次のように定義されています。
```c
unsigned long arch_randomize_brk(struct mm_struct *mm)
{
	return randomize_page(mm->brk, 0x02000000);
}
```
これによりプログラムブレーク（glibc mallocで使われる）のアドレスもランダム化されています。

また、mmapにより確保されるアドレスも、[`mmap_base`](https://elixir.bootlin.com/linux/latest/source/arch/x86/mm/mmap.c#L82)でランダム化されます。
ここで使われる乱数は[`arch_rnd`](https://elixir.bootlin.com/linux/latest/source/arch/x86/mm/mmap.c#L70)で計算されます。
```c
static unsigned long arch_rnd(unsigned int rndbits)
{
	if (!(current->flags & PF_RANDOMIZE))
		return 0;
	return (get_random_long() & ((1UL << rndbits) - 1)) << PAGE_SHIFT;
}
```
ここに渡されるビット数`rndbits`は[`/proc/sys/vm/mmap_rnd_bits`](https://elixir.bootlin.com/linux/latest/source/arch/Kconfig#L979)で調整できます。

最終的に、以下のアドレスがASLRによりランダム化されます。

- スタックのアドレス
- プログラムブレークのアドレス
- mmapのベースアドレス
- プログラム(PIE)およびローダ(interpreter)のロードアドレス

### ASLRの影響を受けない領域とPIE
ASLRが有効になるとスタックやmmapなどさまざまなアドレスがランダム化されることが分かりました。
しかし、アドレスがランダム化されると困る箇所がいくつかあります。
その1つがプログラムそのもののアドレスです。

グローバル変数や文字列定数などは、どの関数からも参照できるため、固定アドレスに設置します。
歴史的にこういったデータは、固定アドレスを機械語中に書いて、直接参照していました。
しかし、プログラムのロードアドレスがランダム化されると、プログラム自身がこれらのデータを参照できなくなってしまいます。

そこで登場するのがPIE(Position Independent Executable)です。
PIEはPIC(Position Independent Code)とも呼ばれ、共有ライブラリのようにマップされるアドレスがわからない場合でも、正しく動くようにコンパイルされたプログラムのことを指します。
グローバル変数といったロードアドレスに依存するアドレスを参照するコードは、すべてRIPからの相対アドレスを使って参照されます。

PIEはELFファイル中の`e_type`が`ET_DYN`であると有効として認識されます。
PIEが有効なプログラムは、ASLRが有効なときロードアドレスがランダム化されます。

<div class="balloon_l">
  <div class="faceicon"><img src="../img/XXX.png" alt="ヒヨコ先生" ></div>
  <p class="says">
    初期値としてポインタを持つ
    PIEが有効な場合、はリロケーションという仕組みで実行ファイル起動時にロードアドレスが加算され、正しいポインタに修正されます。
  </p>
</div>

### NX

NX, W^X

### CET

arch_prctl

## コンパイラやプログラムレベルのセキュリティ機構

### Stack Canary (SSP)

fs


### FORTIFY_SOURCE


### CFI


## ライブラリの緩和策


