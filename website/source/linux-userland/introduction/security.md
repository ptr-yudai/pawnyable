---
title: セキュリティ機構
date: 2023-04-16 19:20:00
tags:
    - [Linux]
    - [Userland]
    - [ASLR]
    - [NX]
    - [CET]
    - [SSP]
    - [Stack Canary]
    - [Fortify]
    - [CFI]
    - [CFG]
lang: ja

pagination: true
fd: primitive.html
---
この章では、Linuxのユーザー空間で登場するセキュリティ機構や、それにまつわる用語について説明します。

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
  <div class="faceicon"><img src="../img/piyo_born.png" alt="ヒヨコ先生" ></div>
  <p class="says">
    PIEが有効な場合、初期値としてポインタを持つ変数はリロケーションという仕組みで実行ファイル起動時にロードアドレスが加算され、正しいポインタに修正されるのです。
  </p>
</div>

### NX

ASLRがOSで実装されるセキュリティ機構であるのに対し、 **NX (No eXecute)** はCPUレベルで実装されるセキュリティ機構です。特にWindowsの文脈では **DEP (Data Execution Prevention)** とも呼ばれます。

NXが有効な場合、実行しようとする機械語が置かれたメモリ領域が実行可能領域（コード領域）かを判定します。仮想メモリアドレスを物理メモリアドレスに変換するためのページテーブルのエントリ中に、NXビットと呼ばれるビットがあります。CPUのメモリ管理ユニット(MMU)がコードをfetchする際に、このビットを確認します。実行可能とマークされていないのに実行しようとした場合、例外が発生します。

NXが有効になることにより、例えばスタックやヒープ上に攻撃者が用意したシェルコードは実行できなくなります。逆に言うと、NXが有効でも実行かつ書き換え可能な領域があると、攻撃に利用される可能性があります。実際、2021年までのV8エンジン（Google Chromeで使われているJavaScriptエンジン）では、動的にコンパイルされるWebAssemblyの機械語領域が実行かつ書き換え可能な状態にあり、exploitに多用されていました。現在は書き換え不可能になっており、使えません。
このように、攻撃を緩和するためには「書き込み可能」と「実行可能」の両方ができる領域をなくすことが大切です。このような設計を、「書き込み可能(Writable)」と「実行可能(Executable)」が排他的であることから、 **W^X(Write XOR eXecute)** と呼びます。

### CET

NXが普及した現在、もっとも一般的なNXの回避方法はROP(Return Oriented Programming)やCOP/JOP(Call/Jump Oriented Programming)です。これらの攻撃手法では、実行可能領域の小さいコード片(gadget)をスタックやvtableなどの制御可能な領域を通して連続的に実行し、一連の処理を実現します。

これらの攻撃を防ぐために2020年あたりから登場したIntelのセキュリティ機構として、 **Intel CET (Control-flow Enforcement Technology)** があります。CETと似たセキュリティ機構は後述するCFIとして古くからありましたが、CETではROP対策がCPUレベルで実現されたという点が強力です。

CETを有効にすると、ROPに使われるスタックのリターンアドレスと、関数テーブルやvtableなどのindirect branchが保護されます。2023年現在一般的なマシンおよびサーバーに使われているCPUにおいてCETはまだ無効なので、詳しい説明は省略します。

原理としては、まず、Shadow Stackと呼ばれるリターンアドレスのコピーが保存された領域を使ってリターンアドレスの書き換えを検知します。さらに、indirect jump/callにおいては、飛び先が`endbr32/64`命令から始まらないと例外を発生します[^1]。

[^1]: つまり、このセキュリティ機構が原因で、Intel機器を対象とする世の中のコンパイラやJITは、すべて`endbr32/64`命令を適切に吐き出すように修正される必要があります。

CPUがCETをサポートしている場合、Linuxでは`arch_prctl`を使ってプロセスごとにCETを有効化・無効化できます。glibcでは、起動時に[CETの確認およびロック](https://elixir.bootlin.com/glibc/glibc-2.37.9000/source/sysdeps/x86/cpu-features.c#L815)が走ります。

## コンパイラやプログラムレベルのセキュリティ機構

ここまでOSやCPUが実装するユーザー空間向けのセキュリティ機構について説明しました。ここからは、アプリケーションが独自で実装する、あるいはコンパイラによりアプリケーションに導入されるセキュリティ機構について説明します。

### Stack Canary (SSP)

スタックバッファオーバーフローに対する代表的なセキュリティ機構として、 **Stack Canary** があげられます。 **SSP(Stack Smashing Protector)** とも呼ばれます。gccやVC++などの代表的なコンパイラはすべてSSPを実装しており、標準で有効化されます。

TODO: つづき

### FORTIFY_SOURCE


### CFI


## ライブラリの緩和策


