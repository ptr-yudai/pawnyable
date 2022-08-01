---
title: 検証器とJITコンパイラ
tags:
    - [Linux]
    - [Kernel]
    - [BPF]
    - [JIT]
lang: ja

pagination: true
fd: exploit.html
bk: ebpf.html
---
[前章](ebpf.html)ではeBPFについて学びました。本章では、ユーザーから渡されたBPFプログラムを安全かつ高速に動かすための、検証器とJITについて説明します。

<div class="column" title="目次">
<!-- toc --><br>
</div>

## 検証器
まずは、eBPFの検証器について学びましょう。検証器のソースコードはLinuxカーネルの[`kernel/bpf/verifier.c`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c)に書かれています。。
検証器は命令を1つずつチェックし、すべての分岐先をexit命令までトレースします。検証は大きく二段階（First Pass, Second Pass）に分けられます。

一段階目のチェックでは、深さ優先探索によってプログラムが有向非巡回グラフ（DAG; Directed Acyclic Graph）であることを保証します。DAGとはループを持たない有向グラフのことです。
このチェックにより、次のようなプログラムは拒否されます。

- `BPF_MAXINSNS`を超える命令が存在する場合[^1]
- ループフローが存在する場合
- 到達不可能な命令が存在する場合
- 範囲外、あるいは不正なジャンプが存在する場合

[^1]: 命令数については、他のチェックがある`check_cfg`以前にチェックされています。

二段階目のチェックでは、あらためてすべてのパスを探索します。このとき、レジスタの値に対して型や範囲を追跡します。
このチェックにより、例えば次のようなプログラムは拒否されます。

- 未初期化レジスタの利用
- カーネル空間のポインタのreturn
- カーネル空間のポインタをBPFマップへ書込
- 不正なポインタの読み書き

### 一段階目のチェック
DAGのチェックは[`check_cfg`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L10186)関数に実装されています。アルゴリズム自体は、再帰呼出を使わない深さ優先探索です。
`check_cfg`はプログラムの先頭から深さ優先探索の要領で命令を見ていきます。現在見ている命令に対して[`visit_insn`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L10121)が呼ばれ、この関数で分岐先がスタックにpushされます。探索用スタックへのpushは[`push_insn`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L10044)で定義されており、この中に範囲外へのジャンプと閉路検出が含まれています。
```c
	if (w < 0 || w >= env->prog->len) {
		verbose_linfo(env, t, "%d: ", t);
		verbose(env, "jump out of range from insn %d to %d\n", t, w);
		return -EINVAL;
	}
...

	} else if ((insn_state[w] & 0xF0) == DISCOVERED) {
		if (loop_ok && env->bpf_capable)
			return DONE_EXPLORING;
		verbose_linfo(env, t, "%d: ", t);
		verbose_linfo(env, w, "%d: ", w);
		verbose(env, "back-edge from insn %d to %d\n", t, w);
		return -EINVAL;
```
なお、`visit_insn`は1回につき、必ず1つのパスしかpushしません。（あるいは`DONE_EXPLORING`でその命令の分岐先がすべて探索終了したことを知らせます。）例えば`BPF_JEQ`のように条件分岐がある場合、`visit_insn`は最初の分岐先のみをpushします。深さ優先探索なので、その分岐先の探索がすべて終了すると、また`BPF_JEQ`に戻ってきます。すると`BPF_JEQ`に対して再度`visit_insn`が呼ばれ、今度はもう一方の分岐先がpushされます。さらにそちらの探索が終了すると、`BPF_JEQ`に対して3回目の`visit_insn`が呼ばれ、そこで`DONE_EXPLORING`が返され、`BPF_JEQ`がスタックからpopされます。

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="オオカミくん" ></div>
  <p class="says">
    条件分岐で一度に両方のパスをpushしなかったり、命令を取り出すときにpopしなかったり、一見非効率的に見えるけど、異常を検知したときに綺麗なスタックトレースを出力するための工夫なんだね。
  </p>
</div>

例えば、次のようなプログラムはすべて一段階目のチェック機構により拒否されます。
```c
// 到達不能な命令がある
struct bpf_insn insns[] = {
  BPF_EXIT_INSN(),
  BPF_MOV64_IMM(BPF_REG_0, 0),
  BPF_EXIT_INSN(),
};
```

```c
// 範囲外へのジャンプがある
struct bpf_insn insns[] = {
  BPF_JMP_IMM(BPF_JA, 0, 0, 2),
  BPF_MOV64_IMM(BPF_REG_0, 0),
  BPF_EXIT_INSN(),
};
```

```c
// ループがある
struct bpf_insn insns[] = {
  BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 123, -1), // jmp if r0 != 123
  BPF_MOV64_IMM(BPF_REG_0, 0),
  BPF_EXIT_INSN(),
};
```

たとえ負の方向へのジャンプがあっても、ループしていなければ問題ありません。
```c
struct bpf_insn insns[] = {
  BPF_MOV64_IMM(BPF_REG_0, 0),
  BPF_JMP_IMM(BPF_JA, 0, 0, 1), // jmp to JEQ
  BPF_JMP_IMM(BPF_JA, 0, 0, 1), // jmp to MOV64
  BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, -2), // jmp to JA(1) if R0==0
  BPF_EXIT_INSN(),
};
```

### 二段階目のチェック
eBPFにおける検証器のバグでもっとも重要になるのは、二段階目のチェックです。
二段階目のチェックは主に[`do_check`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L11450)関数で定義されており、レジスタの型、値の範囲、具体的な値やオフセットを追跡します。

#### 型の追跡
検証器はレジスタの値がどのような種類の値かを[`bpf_reg_state`構造体](https://elixir.bootlin.com/linux/v5.18.11/source/include/linux/bpf_verifier.h#L46)で保持しています。例えば次のような命令を考えましょう。
```
BPF_MOV64_REG(BPF_REG_0, BPF_REG_10)
BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, -8)
```
最初の命令ではスタックポインタを`R0`に代入しています。このとき、`R0`は`PTR_TO_STACK`という型になります。次の命令では`R0`から8だけ引かれますが、まだスタックの範囲内を指しているため、`PTR_TO_STACK`のままです。他にも、ポインタとポインタの足し算は定数扱いになるなど、命令の種類とレジスタの型、値の範囲などに応じて、新しい型は変わります。
型の追跡は、不正なプログラムを調べる上で必須です。例えばスカラー値をポインタとしてメモリからデータをロード・ストアできてしまうと、任意アドレス読み書きになってしまいます。また、コンテキストを受け取るヘルパー関数にBPFマップなど自由に操作できるポインタを指定できてしまうと、偽のコンテキストを使わせることができます。
レジスタの型（[`enum bpf_reg_type`](https://elixir.bootlin.com/linux/v5.18.11/source/include/linux/bpf.h#L493)）としては、例えば以下のような型が定義されています。

| 型 | 意味 |
|:-:|:-:|
| `NOT_INIT` | 未初期化 |
| `SCALAR_VALUE` | 定数など一般的な値 |
| `PTR_TO_CTX` | コンテキスト（BPFプログラムの呼出引数）へのポインタ |
| `CONST_PTR_TO_MAP` | BPFマップへのポインタ |
| `PTR_TO_MAP_VALUE` | BPFマップの値へのポインタ |
| `PTR_TO_MAP_KEY` | BPFマップのキーへのポインタ |
| `PTR_TO_STACK` | BPFスタックへのポインタ |
| `PTR_TO_MEM` | 有効なメモリ領域へのポインタ |
| `PTR_TO_FUNC` | BPF関数へのポインタ |

レジスタの初期状態は[`init_reg_state`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L1570)関数で定義されます。

#### 定数の追跡
検証器ではレジスタの定数を追跡しています。値は区間を使った抽象化で追跡されます。つまり、各レジスタについて、その時点でレジスタが取り得る「最小値」と「最大値」を記録しています。
例えば、`R0 += R1 (BPF_ADD)`の時点で`R0`と`R1`がそれぞれ`[10, 20]`,`[-2, 2]`を取り得る場合、演算（抽象解釈）後の`R0`の値は`[8, 22]`になります。
演算に関するこの挙動は[`adjust_reg_min_max_vals`関数](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L8438)と[`adjust_scalar_min_max_vals`関数](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L8277)で定義されています。

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="オオカミくん" ></div>
  <p class="says">
    具体的な値が分からない解析過程では、値を抽象的な範囲で推測することが多いね。
    健全（sound）な手法で抽象化しないと、解釈結果が間違うことがあるよ。
  </p>
</div>

値の範囲追跡のため、検証器は各レジスタについて次のような値を保持・追跡しています。

| 変数 | 意味 |
|:-:|:-|
| `umin_value`, `umax_value` | 64-bitの符号なし整数として解釈したときの最小・最大値 |
| `smin_value`, `smax_value` | 64-bitの符号付き整数として解釈したときの最小・最大値 |
| `u32_min_value`, `u32_max_value` | 32-bitの符号なし整数として解釈したときの最小・最大値 |
| `s32_min_value`, `s32_max_value` | 32-bitの符号付き整数として解釈したときの最小・最大値 |
| `var_off` | レジスタ中の各ビットの情報（具体的な値が判明しているビット） |

`var_off`は`tnum`と呼ばれる構造体で、`mask`と`value`を持ちます。`mask`は値が不明なビットの場所が1になっています。`value`は判明している場所の値です。
例えば、BPFマップから取得した64ビットの値は、最初すべてのビットが不明なので、`var_off`は
```
(mask=0xffffffffffffffff; value=0x0)
```
になります。このレジスタに対して0xffff0000をANDすると、0とANDした箇所は0になることが分かるので、
```
(mask=0xffff0000; value=0x0)
```
になります。更に0x12345を足すと、下位16ビットは分かるので
```
(mask=0x1ffff0000; value=0x2345)
```
となります。繰り上がりの可能性を考慮して`mask`のビットが1つ増えていることに注意してください。この時点での`umin_value`, `umax_value`, `u32_min_value`, `u32_max_value`はそれぞれ、0x1ffff0000, 0x1ffff2345, 0xffff0000, 0xffff2345です。


では、具体的な実装を見てみましょう。`BPF_ADD`の場合、次のようにレジスタが更新されます。
```c
	case BPF_ADD:
		scalar32_min_max_add(dst_reg, &src_reg);
		scalar_min_max_add(dst_reg, &src_reg);
		dst_reg->var_off = tnum_add(dst_reg->var_off, src_reg.var_off);
		break;
```
`scalar_min_max_add`では、次のように整数オーバーフローなども考慮した範囲計算が実装されています。
```c
static void scalar_min_max_add(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	s64 smin_val = src_reg->smin_value;
	s64 smax_val = src_reg->smax_value;
	u64 umin_val = src_reg->umin_value;
	u64 umax_val = src_reg->umax_value;

	if (signed_add_overflows(dst_reg->smin_value, smin_val) ||
	    signed_add_overflows(dst_reg->smax_value, smax_val)) {
		dst_reg->smin_value = S64_MIN;
		dst_reg->smax_value = S64_MAX;
	} else {
		dst_reg->smin_value += smin_val;
		dst_reg->smax_value += smax_val;
	}
	if (dst_reg->umin_value + umin_val < umin_val ||
	    dst_reg->umax_value + umax_val < umax_val) {
		dst_reg->umin_value = 0;
		dst_reg->umax_value = U64_MAX;
	} else {
		dst_reg->umin_value += umin_val;
		dst_reg->umax_value += umax_val;
	}
}
```
乗除や論理・算術シフトなど、すべての演算に対してこのような更新処理が実装されています。計算した値の範囲は、スタックやコンテキストなどのメモリアクセスにおいて、オフセットが範囲内に収まっているかを確認するのに使われます。
例えば、スタックの範囲チェックは[`check_stack_access_within_bounds`](https://elixir.bootlin.com/linux/v5.18.11/source/kernel/bpf/verifier.c#L4315)で定義されています。即値の場合など、値が定数と分かっている場合は通常のオフセットチェックをします。
```c
	if (tnum_is_const(reg->var_off)) {
		min_off = reg->var_off.value + off;
		if (access_size > 0)
			max_off = min_off + access_size - 1;
		else
			max_off = min_off;
```
一方で具体的な値がわからない場合は、オフセットが取り得る最小・最大値を確認します。
```c
	} else {
		if (reg->smax_value >= BPF_MAX_VAR_OFF ||
		    reg->smin_value <= -BPF_MAX_VAR_OFF) {
			verbose(env, "invalid unbounded variable-offset%s stack R%d\n",
				err_extra, regno);
			return -EACCES;
		}
		min_off = reg->smin_value + off;
		if (access_size > 0)
			max_off = reg->smax_value + off + access_size - 1;
		else
			max_off = min_off;
	}
```
そして、それらの値を使って範囲チェックをしています。
```c
	err = check_stack_slot_within_bounds(min_off, state, type);
	if (!err)
		err = check_stack_slot_within_bounds(max_off, state, type);
```
このように、レジスタや変数の値の範囲を追跡する手法は、BPF以外でも、最適化・高速化が要求されるJITで頻繁に使われます。

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="オオカミくん" ></div>
  <p class="says">
    実行速度向上のために、できるだけ事前にセキュリティチェックを終わらせているんだね。
  </p>
</div>

次のようなプログラムはすべて二段階目のチェック機構により拒否されます。
```c
// 未初期化のレジスタの利用
struct bpf_insn insns[] = {
  BPF_MOV64_REG(BPF_REG_0, BPF_REG_5),
  BPF_EXIT_INSN(),
};
```

```c
// カーネル空間のポインタのリーク
struct bpf_insn insns[] = {
  BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
  BPF_EXIT_INSN(),
};
```

抽象化された値が定数にならない例を考えてみましょう。
```c
int mapfd = map_create(0x10, 1);

struct bpf_insn insns[] = {
  BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 0),      // key=0
  // arg1: mapfd
  BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
  // arg2: key pointer
  BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
  BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
  // map_lookup_elem(mapfd, &key)
  BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
  // jmp if success (R0 != NULL)
  BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
  BPF_EXIT_INSN(), // exit on failure

  BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0),   // R6 = arr[0]
  BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),            // R7 = &arr[0]

  BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 0b0111),    // R6 &= 0b0111
  BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6), // R7 += R6
  BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_7, 0), // R0 = [R7]
  BPF_EXIT_INSN(),
};
```
まず、値のサイズが0x10のBPFマップを用意しています。BPFプログラムの最初のブロックでは、BPFマップの先頭の値と、そのポインタをそれぞれ`R6`, `R7`に代入します。（`map_lookup_elem`の戻り値`R0`は、第二引数のインデックスで指定した要素へのポインタです。NULLを返す可能性があるため、条件分岐でNULLを除去しています。）
最後のブロックでポインタ`R7`に`R6`の値を加算しています。`R6`はBPFマップから取ってきた値なので任意の値を取れます。しかし、`BPF_AND`で0b0111とandを取っているため、この時点で`R6`の取り得る値は[0, 7]になります。今回BPFマップ値のサイズは0x10にしてあるため、値のポインタの先頭から7足して、そこから`BPF_LDX_MEM(BPF_DW)`で8バイト取得しても問題ありません。そのため、このBPFプログラムは検証器を通過できます。
しかし、`BPF_AND`の値を0b1111などにすると、検証器がプログラムを拒否することが分かります。
```
...
11: (0f) r7 += r6
 R0=map_value(id=0,off=0,ks=4,vs=16,imm=0) R6_w=invP(id=0,umax_value=15,var_off=(0x0; 0xf)) R7_w=map_value(id=0,off=0,ks=4,vs=16,umax_value=15,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmmmmmm
12: R0=map_value(id=0,off=0,ks=4,vs=16,imm=0) R6_w=invP(id=0,umax_value=15,var_off=(0x0; 0xf)) R7_w=map_value(id=0,off=0,ks=4,vs=16,umax_value=15,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmmmmmm
12: (79) r0 = *(u64 *)(r7 +0)
 R0_w=map_value(id=0,off=0,ks=4,vs=16,imm=0) R6_w=invP(id=0,umax_value=15,var_off=(0x0; 0xf)) R7_w=map_value(id=0,off=0,ks=4,vs=16,umax_value=15,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmmmmmm
invalid access to map value, value_size=16 off=15 size=8
R7 max value is outside of the allowed memory range
processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1

bpf(BPF_PROG_LOAD): Permission denied
```
値のサイズが16なのに、最大オフセットは15で、そこから8バイト取得しようとしているため、範囲外参照が起きるためです。
また、一部の命令は値の追跡をサポートしていません。例えば`BPF_NEG`を通ると必ずunboundになるため、次のプログラムは（実際には問題ないですが）検証器に拒否されます。
```
  BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 0b0111),    // R6 &= 0b0111
  BPF_ALU64_IMM(BPF_NEG, BPF_REG_6, 0),         // R6 = -R6 (追加)
  BPF_ALU64_IMM(BPF_NEG, BPF_REG_6, 0),         // R6 = -R6 (追加)
  BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6), // R7 += R6
  BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_7, 0), // R0 = [R7]
```

このように、二段階目のチェックではレジスタを追って、メモリアクセスやレジスタ利用時に未定義動作が起きないことを保証しています。逆に言えば、この**チェックが間違っていると、メモリアクセスで範囲外参照を起こせてしまう**わけです。具体的な手法は次の章で説明します。

#### ALU sanitation
ここまで説明した型チェック・範囲追跡が検証器の仕事なのですが、eBPFを悪用する攻撃が増えたため、近年では新たにALU sanitationという緩和機構が導入されています。
検証器のミスにより攻撃が発生する原因は、範囲外参照を起こせるためです。例えば下図のように、検証器が0と推測しているのに実際の値が32の「壊れた」レジスタができたとします。攻撃者は図のように、サイズ8の値を4つ持つマップのポインタに壊れた値を足します。検証器は値を0だと思っているので、加算後もマップの先頭を指したままだと思っていますが、実際には範囲外を指しています。この状態でR1から値をロードすると、検証器に検知されることなく範囲外参照ができます。

<center>
  <img src="img/simple_oob.png" alt="推測値の誤りによる範囲外参照" style="width:640px;">
</center>

このような検証器の誤りによる範囲外参照を解決するため、ALU sanitationという緩和機構が[2019年に導入](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=979d63d50c0c0f7bc537bf821e056cc9fe5abd38)されました。[^2]

[^2]: ALU sanitationは実装にバグがあったため、[2021年に修正](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=10d2bb2e6b1d8c4576c56a748f697dbeb8388899)されました。

eBPFでは、ポインタに対してはスカラー値の足し引きだけが演算として許可されています。ALU sanitationでは、ポインタとスカラー値の足し引きにおいて、スカラー値側が定数であると分かっているとき、それを定数演算`BPF_ALUxx_IMM`に書き換えます。例えば、R1がマップのポインタで、R2が推測値0、実際値1のスカラー値を持つレジスタだとします。このとき
```
BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2)
```
は、検証器がR2を定数0だと思っているため、
```
BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 0)
```
に[変更されます](https://elixir.bootlin.com/linux/v5.18.14/source/kernel/bpf/verifier.c#L13348)。このパッチはもともとSpectreというサイドチャネル攻撃を防ぐために導入されたものですが、検証器のバグを悪用する攻撃にも効果があります。

さらに、スカラー側が定数でない場合は、`alu_limit`という値を用いて命令がパッチされます。
`alu_limit`は「そのポインタから最大でどれだけの値を足し引きできるか」を示す数値です。例えばサイズ0x10のマップ要素の先頭から2バイト目を指していて、`BPF_ADD`によるスカラー値との加算が発生する場合、`alu_limit`は0xeになります。先ほどと同じように
```
BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG2)
```
という命令を考えます。ALU sanitationでは、この命令が次のように[パッチされます](https://elixir.bootlin.com/linux/v5.18.14/source/kernel/bpf/verifier.c#L13350)。（`BPF_REG_AX`は補助レジスタです。）
```
BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit),
BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, off_reg),
BPF_ALU64_REG(BPF_OR, BPF_REG_AX, off_reg),
BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0),
BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63),
BPF_ALU64_REG(BPF_AND, BPF_REG_AX, off_reg),
```
先ほどと同じく、サイズ0x10のマップ要素の先頭から2バイト目を指しているレジスタR1に対するスカラー値R2の加算を考えます。スカラー値R2が`alu_limit`である0xeを超えているにも関わらず、何かしらのバグで検証器が検知できていないとします。例えば、次のような命令列が生成されます。
```
BPF_MOV32_IMM(BPF_REG_AX, 0xe),
BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, BPF_REG_R2),
BPF_ALU64_REG(BPF_OR, BPF_REG_AX, BPF_REG_R2),
BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0),
BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63),
BPF_ALU64_REG(BPF_AND, BPF_REG_AX, BPF_REG_R2),
```
まず、最初の2命令で0xe-R2を計算します。R2が範囲内の場合は正の値あるいはゼロになりますが、範囲外の場合は負の値になります。次のOR命令では、AXとR2が異なる符号を持つ場合に、最上位ビットが1になります。つまり、範囲外参照が起きる時は、この時点で最上位ビットが1になっているはずです。
その後NEGで符号を反転させ、算術シフトで64ビットシフトます。範囲外参照が起きる場合はAXに0が、そうでなければAXに0xffffffffffffffffが入ります。最後にR2とAXのANDを取り、これが最終的に使われるオフセットとなります。

この操作により、万が一範囲外参照が発生する状況になったら、ポインタに0が加算されるようになります。

## JIT (Just-In-Time compiler)
検証器を通過したBPFプログラムは、どのような入力で実行しても安全であることが（検証器が正しいという仮定の下で）保証されています。したがって、JITコンパイラは与えられた命令をCPUに合った機械語に直接変換することになります。
CPUごとに機械語は異なるため、JITのコードは`arch`ディレクトリ以下に書かれています。x86-64の場合、[`arch/x86/net/bpf_jit_comp.c`](https://elixir.bootlin.com/linux/v5.18.11/source/arch/x86/net/bpf_jit_comp.c)中の[`do_jit`関数](https://elixir.bootlin.com/linux/v5.18.11/source/arch/x86/net/bpf_jit_comp.c#L875)に記述されています。
例えば、乗算（`BPF_MUL`）を機械語に変換するコードは以下のようになっています。
```c
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU64 | BPF_MUL | BPF_X:
			maybe_emit_mod(&prog, src_reg, dst_reg,
				       BPF_CLASS(insn->code) == BPF_ALU64);

			/* imul dst_reg, src_reg */
			EMIT3(0x0F, 0xAF, add_2reg(0xC0, src_reg, dst_reg));
			break;
```
`0x0F, 0xAF`が`imul`命令に対応する命令コードになります。

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_atamawaru.png" alt="オオカミくん" ></div>
  <p class="says">
    検証器が正しくても、JITで生成されるコードが検証器と違う挙動をしたら、それもexploitableになりそうだね。
  </p>
</div>

ここまででexploitに必要なeBPF内部の仕組みを概ね説明しました。次章では、実際に検証器のバグを利用して権限昇格していきます。

---

<div class="column" title="例題">
  次の処理が検証器に許可されるかを調べてください。拒否される場合、それができるとセキュリティ上何が問題になるかを説明してください。<br>
  (1) ポインタどうしの比較<br>
  (2) ポインタとポインタの加算<br>
  (3) ポインタとポインタの排他的論理和<br>
  (4) BPFマップへのポインタ値の書き込み<br>
</div>

