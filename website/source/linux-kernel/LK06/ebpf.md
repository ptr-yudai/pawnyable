---
title: BPFの導入
tags:
    - [Linux]
    - [Kernel]
    - [BPF]
    - [JIT]
lang: ja

pagination: true
fd: verifier.html
---
LK06(Brahman)では、Linuxカーネルの機能の1つである、eBPFに含まれるJIT（検証器）のバグを攻撃します。この章では、まずBPFという機能と、その使い方について学びます。

<div class="column" title="目次">
<!-- toc --><br>
</div>

## BPF
eBPFについて説明する前に、その前身となるBPFについて説明します。
BPFは時代とともに利用用途が広がり、拡張が進みました。大幅な変更が入ってからのBPFをeBPF(extended BPF)、それ以前のBPFをcBPF(classic BPF)と区別して表記することもあります。しかし、現在のLinuxでは、内部的にはeBPFのみが利用されているため、本サイトでは明確に区別が必要ないときはeBPF/cBPFをまとめてBPFと呼びます。

### BPFとは
**BPF**(Berkeley Packet Filter)とは、Linuxカーネルが持つ独自のRISC型仮想マシンです。ユーザー空間から渡されたコードをカーネル空間で実行するために用意されています。当然、任意のコードを実行されては危険なので、BPFに存在する命令セットは、演算や条件分岐といった安全な命令がほとんどです。しかし、メモリ書き込みやジャンプなどの、安全性が保証できない命令も含まれているため、バイトコードを受理する際に**検証器**を通します。これにより、（例えば無限ループに陥らないような）安全なプログラムのみ実行できます。
では、なぜここまでしてユーザー空間からカーネル空間でコードを実行する必要があるのでしょうか。
BPFは設計当初、パケットフィルタリングを目的に作られました。ユーザーがBPFコードをロードしておくと、通信パケットが発生したタイミングでBPFコードが実行され、フィルタリングに利用できます。現在ではパケットフィルタリング以外にも、実行トレースの取得や、seccompがシステムコールをフィルタする仕組みなどにもBPFが利用されています。

このように、パケットフィルタやseccompなど、さまざまな箇所でBPFが利用されるようになりました。しかし、毎回BPFバイトコードを解釈してエミュレートしていては、実行速度に難があります。そこで、検証器を通過したBPFバイトコードは、**JIT**(Just-in-Time)コンパイラにより、CPUが解釈できる機械語に変換されます。
JITコンパイラとは、プログラムの実行中など動的に、何かしらのコードをネイティブな機械語に変換してくれる機構を指します。例えばChromeやFirefoxなどのブラウザは、何回も呼び出されるJavaScript関数を見つけたら、それを機械語に変換して、以降は機械語側を実行することで高速化しています。LinuxカーネルのBPFにおいてJITコンパイラが利用されるかはオプション次第ですが、現在のLinuxカーネルでは標準でJITコンパイラが有効化されています。

整理すると、BPFコードが実行されるまでの流れは次のようになります。

1. ユーザー空間からbpfシステムコールでBPFバイトコードがカーネル空間に渡される。
2. バイトコードを実行しても安全かを、検証器が確かめる。
3. 検証に成功したら、JITコンパイラでCPUに対応した機械語に変換する。
4. イベントが発生したら、JITコンパイル後の機械語が呼ばれる。

<center>
  <img src="img/bpf_load.png" alt="BPFのロード" style="width:640px;">
</center>

イベントが発生すると、登録したBPF（チェックしたいイベント）の種類によって引数が渡されます。この引数を**コンテキスト**と呼びます。BPFはその引数を処理をして、最終的に1つの返り値を返します。例えばseccompの場合、呼ばれようとしたシステムコールの番号やアーキテクチャの種類などが入った構造体が引数としてBPFプログラムに渡ります。BPFプログラム（seccomp filter）はシステムコール番号などをもとに、システムコールの実行を許可するかなどを判断し、返り値としてカーネルに受け渡します。この返り値を受け取ったカーネルは、システムコールを許可するか、拒否するか、それとも失敗させるかなどを判断できます。

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_normal.png" alt="オオカミくん" ></div>
  <p class="says">
    seccompは今でもcBPFを使っているけど、カーネル内部ではeBPFしか使ってないから、最初にeBPFに変換されるよ。それから、seccompにはBPFの検証器に加えて独自の検証機構があるよ。
  </p>
</div>

また、BPFプログラムとユーザー空間がやりとりするためには**BPFマップ**というものを使います。BPFではカーネル空間にマップという、key-valueペアの連想配列[^1]を作れます。これについての詳細は、実際にBPFプログラムを書く際に見ていきます。

[^1]: マップには種類が設定できますが、`BPF_MAP_TYPE_ARRAY`の場合、キーは整数値で上限も設定するので、ただの配列になります。

### BPFのアーキテクチャ
より詳しくBPFの構造を見ていきましょう。cBPFは32ビットのアーキテクチャでしたが、eBPFでは近年のアーキテクチャに合わせて64ビットになり、レジスタの数も増えました。ここではeBPFのアーキテクチャを説明します。

#### レジスタとスタック
BPFプログラムでは512バイトのスタックを利用できます。eBPFでは、以下のレジスタが用意されています。

| BPFレジスタ | 対応するx64のレジスタ |
|:-:|:-:|
| R0 | rax |
| R1 | rdi |
| R2 | rsi |
| R3 | rdx |
| R4 | rcx |
| R5 | r8 |
| R6 | rbc |
| R7 | r13 |
| R8 | r14 |
| R9 | r15 |
| R10 | rbp |

`R10`以外のレジスタは、BPFプログラム中で汎用レジスタとして扱えますが、いくつか特殊な意味を持つレジスタがあります。
まず、カーネル側から渡されるコンテキスト（ポインタ）が`R1`に入ります。BPFプログラムは通常、このコンテキストの内容を処理することになります。例えばソケットフィルタの場合、コンテキストからパケットデータを取り出すなどが可能です。
そして、`R0`レジスタはBPFプログラムの戻り値として利用されます。そのため、BPFプログラムを終了（`BPF_EXIT_INSN`）する前に必ず`R0`に値を設定する必要があります。終了コードには意味があり、例えばseccompの場合はシステムコールを許可・拒否するかなどを表します。
次に、`R1`から`R5`は、カーネル中の関数（後述するヘルパー関数）をBPFプログラムから呼び出すときの引数レジスタとして利用されます。
最後に、`R10`はスタックのフレームポインタで、読み込み専用となっています。

#### 命令セット
一般ユーザーがロードするBPFプログラムは、最大4096命令[^2]を使えます。

[^2]: rootユーザーの場合、最大100万個の命令をロードできます。

BPFはRISC型のアーキテクチャなので、すべての命令は同じサイズになっています。各命令は64ビットで、次のように各ビットが意味を持ちます。

| ビット | 名前 | 意味 |
|:-:|:-:|:-:|
| 0-7 | `op` | オペコード |
| 8-11 | `dst_reg` | 宛先レジスタ |
| 12-15 | `src_reg` | ソースレジスタ |
| 16-31 | `off` | オフセット |
| 32-63 | `imm` | 即値 |

オペコード`op`は、最初の4ビットがコード、次の1ビットがソース、残りの3ビットがクラスを表します。
クラスは命令の種類（メモリ書き込み、算術演算など）を指定します。ソースは、ソースオペランドがレジスタか即値かを決めます。そしてコードが、クラス中の具体的な命令番号を指定します。

BPFの命令セットは[Linuxカーネルのドキュメント](https://www.kernel.org/doc/html/latest/bpf/instruction-set.html)に記載されています。

#### プログラムタイプ
先の例で実際にBPFを試したときは、`BPF_PROG_TYPE_SOCKET_FILTER`というタイプを指定しました。このように、BPFプログラムを何の用途で使うかを、ロード時に指定する必要があります。
cBPFではソケットフィルタとシステムコールフィルタの2種類しかありませんでしたが、eBPFでは20以上のタイプが用意されています。

タイプ一覧は[uapi/linux/bpf.h](https://elixir.bootlin.com/linux/v5.18.10/source/include/uapi/linux/bpf.h#L922)に定義されています。

例えば、`BPF_PROG_TYPE_SOCKET_FILTER`は、cBPFでも使えるソケットフィルタの用途です。BPFプログラムの戻り値によって、パケットをドロップするなどの操作が可能です。このタイプのBPFプログラムは、`SO_ATTACH_BPF`オプションで`setsockopt`システムコールを呼ぶことで、ソケットにアタッチできます。
コンテキストとして[`__sk_buff`構造体](https://elixir.bootlin.com/linux/v5.18.10/source/include/uapi/linux/bpf.h#L5543)が渡されます。

<div class="balloon_l">
  <div class="faceicon"><img src="../img/wolf_suyasuya.png" alt="オオカミくん" ></div>
  <p class="says">
    Linuxカーネルのsk_buff構造体をそのまま渡すとカーネルのバージョンに依存しちゃうから、BPF用に構造を揃えているよ。
  </p>
</div>

#### ヘルパー関数
レジスタの項で少し説明があったように、BPFプログラムから呼び出せる関数があります。例えばソケットフィルタの場合、ベースとなるヘルパー関数に加えて[4つの関数が提供](https://elixir.bootlin.com/linux/v5.18.10/source/net/core/filter.c#L7637)されています。
```c
static const struct bpf_func_proto *
sk_filter_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_skb_load_bytes:
		return &bpf_skb_load_bytes_proto;
	case BPF_FUNC_skb_load_bytes_relative:
		return &bpf_skb_load_bytes_relative_proto;
	case BPF_FUNC_get_socket_cookie:
		return &bpf_get_socket_cookie_proto;
	case BPF_FUNC_get_socket_uid:
		return &bpf_get_socket_uid_proto;
	case BPF_FUNC_perf_event_output:
		return &bpf_skb_event_output_proto;
	default:
		return bpf_sk_base_func_proto(func_id);
	}
}
```
ベースとなるヘルパー関数には、BPFマップを扱う`map_lookup_elem`や`map_update_elem`などがあります。各関数の具体的な使い方は、実際にBPFプログラムを書きながら学びましょう。

## BPFの利用
それでは、実際にBPF(eBPF)を利用してみましょう。

LK06のマシン上でテストする場合は問題ありませんが、みなさんの使っているマシンでテストする場合は、まずBPFが一般ユーザーから使えるかを確認してください。この記事を書いた時点では、Spectreなどのサイドチャネル攻撃の防止のため、一般ユーザーからはBPFが利用できなくなっています。有効かは`/proc/sys/kernel/unprivileged_bpf_disabled`から確認できます。
```
$ cat /proc/sys/kernel/unprivileged_bpf_disabled
2
```
この値が0なら`CAP_SYS_ADMIN`を持っていないユーザーからもBPFが利用できます。1か2になっている場合は、一時的に0に書き換えましょう。

### BPFプログラムの記述
パケットフィルタリングなどの複雑なコードを書く場合は、通常[BCC](https://github.com/iovisor/bcc)のようなコンパイラを使って、C言語などより高級な言語で記述します。今回はexploit目的に軽く使うだけなので、コンパイラを使わずにBPFバイトコードを直接記述しましょう。直接といってもバイトコードを16進数で書く訳ではありません。アセンブリ言語のように、人間にわかりやすい形で書けるC言語用のマクロが用意されています。
まずは、このマクロが定義された[bpf\_insn.h](distfiles/bpf_insn.h)をダウンロードして、テスト用のCコードと同じフォルダに入れておきましょう。

まずは、何もしないBPFプログラムを実行してみます。
```c
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include "bpf_insn.h"

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int bpf(int cmd, union bpf_attr *attrs) {
  return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int main() {
  char verifier_log[0x10000];

  /* BPFプログラムの用意 */
  struct bpf_insn insns[] = {
    BPF_MOV64_IMM(BPF_REG_0, 4),
    BPF_EXIT_INSN(),
  };

  /* 使用用途を設定（ソケットのフィルター） */
  union bpf_attr prog_attr = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = sizeof(insns) / sizeof(insns[0]),
    .insns = (uint64_t)insns,
    .license = (uint64_t)"GPL v2",
    .log_level = 2,
    .log_size = sizeof(verifier_log),
    .log_buf = (uint64_t)verifier_log
  };

  /* BPFプログラムをロード */
  int progfd = bpf(BPF_PROG_LOAD, &prog_attr);
  if (progfd == -1) {
    fatal("bpf(BPF_PROG_LOAD)");
  }

  /* ソケットを作成 */
  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    fatal("socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
    fatal("setsockopt");

  /* ソケットを利用（BPFプログラムの発動） */
  write(socks[1], "Hello", 5);

  char buf[0x10] = {};
  read(socks[0], buf, 0x10);
  printf("Received: %s\n", buf);

  return 0;
}
```
このコードでは、ソケットに対してBPFプログラムをロード（`BPF_PROG_TYPE_SOCKET_FILTER`）します。そのため、最後の`write`をトリガーとして、BPFプログラムが実行されます。

以下の部分がBPFプログラムになります。
```c
  struct bpf_insn insns[] = {
    BPF_MOV64_IMM(BPF_REG_0, 4),
    BPF_EXIT_INSN(),
  };
```
この例では、R0に64ビットの即値4を代入し、プログラムを終了します。正常に動作した場合、"Hell"と出力されるはずです。
レジスタについては後で詳しい説明がありますが、R0レジスタはBPFプログラムの戻り値として利用されます。今回`write`で5文字送信したにも関わらず4文字しか受信できていないのは、BPFがパケットをドロップしたからです。つまり、戻り値によって送信データをカットできるわけです。実際に、`socket`のマニュアルには次のように書かれています。

> SO_ATTACH_FILTER (since Linux 2.2), SO_ATTACH_BPF (since Linux 3.19)
>
>    Attach a classic BPF (SO_ATTACH_FILTER) or an extended BPF (SO_ATTACH_BPF) program to the socket for use as a filter of incoming packets.  **A packet will be dropped if the filter program returns zero.  If the filter program returns a nonzero value which is less than the packet's data length, the packet will be truncated to the length returned.** If the value returned by the filter is greater than or equal to the packet's data length, the packet is allowed to proceed unmodified.

### BPFマップの利用
ここまでで、BPFを使ってパケットをフィルタリングできることを確かめました。
次に、eBPFのexploitで必ずといって良いほど利用する、BPFマップを使ってみます。ユーザー空間（BPFプログラムをロードした側）と、カーネル空間で動くBPFプログラムがやりとりするために、BPFマップが利用されます。
BPFマップを作るには、`BPF_MAP_CREATE`で`bpf`システムコールを呼びます。このとき渡す`bpf_attr`構造体は、タイプを`BPF_MAP_TYPE_ARRAY`にして、配列のサイズやキー・値のサイズを指定します。exploitの文脈ではキーは小さいて良いので、キーはint型として固定します。
```c
int map_create(int val_size, int max_entries) {
  union bpf_attr attr = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = val_size,
    .max_entries = max_entries
  };
  int mapfd = bpf(BPF_MAP_CREATE, &attr);
  if (mapfd == -1) fatal("bpf(BPF_MAP_CREATE)");
  return mapfd;
}
```
配列中の値の更新は`BPF_MAP_UPDATE_ELEM`、取得は`BPF_MAP_LOOKUP_ELEM`で実現できます。
```c
int map_update(int mapfd, int key, void *pval) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key = (uint64_t)&key,
    .value = (uint64_t)pval,
    .flags = BPF_ANY
  };
  int res = bpf(BPF_MAP_UPDATE_ELEM, &attr);
  if (res == -1) fatal("bpf(BPF_MAP_UPDATE_ELEM)");
  return res;
}

int map_lookup(int mapfd, int key, void *pval) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key = (uint64_t)&key,
    .value = (uint64_t)pval,
    .flags = BPF_ANY
  };
  return bpf(BPF_MAP_LOOKUP_ELEM, &attr); // -1 if not found
}
```
次のようなプログラムで動作を確認してみてください。マップの値を（ユーザー空間で）読み書きできていることが分かるでしょう。
```c
  unsigned long val;
  int mapfd = map_create(sizeof(val), 4);

  val = 0xdeadbeefcafebabe;
  map_update(mapfd, 1, &val);

  val = 0;
  map_lookup(mapfd, 1, &val);
  printf("0x%lx\n", val);
```

さて、次にBPFマップをBPFプログラム側から操作してみます。
```c
  /* BPFマップの用意 */
  unsigned long val;
  int mapfd = map_create(sizeof(val), 4);

  val = 0xdeadbeefcafebabe;
  map_update(mapfd, 1, &val);

  /* BPFプログラムの用意 */
  struct bpf_insn insns[] = {
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 1),      // key=1
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x10, 0x1337), // val=0x1337
    // arg1: mapfd
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
    // arg2: key pointer
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
    // arg3: value pointer
    BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_2),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -8),
    // arg4: flags
    BPF_MOV64_IMM(BPF_REG_ARG4, 0),

    BPF_EMIT_CALL(BPF_FUNC_map_update_elem), // map_update_elem(mapfd, &k, &v)

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

...

  /* ソケットを利用（BPFプログラムの発動） */
  map_lookup(mapfd, 1, &val);
  printf("val (before): 0x%lx\n", val);

  write(socks[1], "Hello", 5);

  map_lookup(mapfd, 1, &val);
  printf("val (after) : 0x%lx\n", val);
```
このBPFプログラムは、`map_update_elem`ヘルパー関数を使って、BPFマップ中のキー1の値を0x1337に変更します。
まず、`map_update_elem`にはキー・値ともにポインタを渡すので、メモリ上にキーと値を用意します。
```c
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 1),      // key=1
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x10, 0x1337), // val=0x1337
```
`BPF_REG_FP`は`R10`のことで、スタックポインタとなります。`BPF_ST_MEM`は、馴染みのあるx86-64アセンブリで書くと、次のようになります。
```
mov dword [rsp-0x08], 1
mov dword [rsp-0x10], 0x1337
```
次に、引数を用意します。引数は`BPF_REG_ARG1`から順に入れますが、これは`R1`からのレジスタです。
`map_update_elem`の第一引数はBPFマップのファイルディスクリプタです。`BPF_LD_MAP_FD`を使ってレジスタに代入できます。
```c
    // arg1: mapfd
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
```
第二引数と第三引数は、それぞれキー、値へのポインタです。
```c
    // arg2: key pointer
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
    // arg3: value pointer
    BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_2),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -8),
```
第四引数はフラグですが、0を入れておきます。
```
    // arg4: flags
    BPF_MOV64_IMM(BPF_REG_ARG4, 0),
```
最後に`BPF_EMIT_CALL`を使ってヘルパー関数を呼び出せます。
```c
    BPF_EMIT_CALL(BPF_FUNC_map_update_elem), // map_update_elem(mapfd, &k, &v)
```
実行すると、BPFプログラムが発火する`write`命令前後でBPFマップ中のキー1の値が変化していることが分かります。
```
$ ./a.out 
val (before): 0xdeadbeefcafebabe
val (after) : 0x1337
```

ここまででBPFの基礎は終わりです。このように、BPFプログラミングでは、BPFマップやヘルパー関数を駆使してパケットフィルタなどが実装できます。
次の章では、BPF関連の脆弱性でもっとも重要となる検証器のお話をします。

---

<div class="column" title="例題">
  本章では、BPFプログラムからパケットを部分的にドロップしました。BPFプログラムから次の操作ができるかを調べ、可能な場合はBPFプログラムを書いてください。（ヒント：<code>skb_load_bytes</code>などのヘルパー関数を調べる。）<br>
  (1) 送信データに"evil"という文字列が含まれていたらドロップする。<br>
  (2) 送信データサイズが4バイト以上の場合、先頭4バイトを"evil"に変更する。
</div>
