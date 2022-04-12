---
title: セキュリティ機構
date: 2021-09-22 17:01:30
tags:
    - [Linux]
    - [Kernel]
    - [SMAP]
    - [SMEP]
    - [KASLR]
    - [FGKASLR]
    - [KPTI]
    - [KAISER]
lang: ja
---
カーネルexploitへの緩和策として、Linuxカーネルにはセキュリティ機構がいくつか存在します。ユーザーランドで登場したNXのように、ハードウェアレベルでのセキュリティ機構も存在するため、いくつかの知識はWindowsのカーネルexploitにもそのまま適用できます。

ここで取り上げるのはカーネル特有の保護策で、Stack Canaryのようなセキュリティ機構はデバイスドライバにも存在しますが、それについては特筆すべき点はないためここでは説明しません。

カーネル起動時のパラメータについては[公式のドキュメント](https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/kernel-parameters.txt)が分かりやすいです。

<div class="column" title="目次">
<!-- toc --><br>
</div>

## SMEP (Supervisor Mode Execution Prevention)
カーネルのセキュリティ機構として代表的なものが、SMEPとSMAPです。
SMEPはカーネル空間のコードを実行中に、突然ユーザー空間のコードを実行するのを禁止するセキュリティ機構です。イメージとしてはNXに似ています。

SMEPは緩和機構で、それ単体で強い防御策という訳ではありません。例えばカーネル空間の脆弱性を利用して攻撃者にRIPを奪われてしまったとします。もしSMEPが無効だと、次のようにユーザー空間に用意したシェルコードを実行されてしまいます。
```c
char *shellcode = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXECUTE,
                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
memcpy(shellcode, SHELLCODE, sizeof(SHELLCODE));

control_rip(shellcode); // RIP = shellcode
```
しかしSMEPが有効の場合、上のようにユーザー空間に用意したシェルコードを実行しようとするとカーネルパニックを引き起こします。これにより、攻撃者はRIPを奪っても権限昇格に繋げられなくなる可能性が上がります。

<div class="balloon_l">
  <div class="faceicon"><img src="../img/cow.jpg" alt="牛さん" ></div>
  <p class="says">
    カーネル空間のシェルコードで何を実行するかはまた別の章で勉強するよ。
  </p>
</div>

SMEPはqemu実行時の引数で有効化できます。次のように`-cpu`オプションに`+smep`と付いていればSMEPが有効化されます。
```
-cpu kvm64,+smep
```
マシン内部からは`/proc/cpuinfo`を見ることでも確認できます。
```
$ cat /proc/cpuinfo | grep smep
```

SMEPはハードウェアのセキュリティ機構です。CR4レジスタの21ビット目を立てるとSMEPが有効になります。

## SMAP (Supervisor Mode Access Prevention)
ユーザー空間からカーネル空間のメモリを読み書きできないのはセキュリティ上当たり前ですが、実はカーネル空間からユーザー空間のメモリを読み書きできなくする**SMAP**(Supervisor Mode Access Prevention)というセキュリティ機構が存在します。カーネル空間からユーザー空間のデータを読み書きするには、[`copy_from_user`](https://www.kernel.org/doc/htmldocs/kernel-api/API---copy-from-user.html), [`copy_to_user`](https://www.kernel.org/doc/htmldocs/kernel-api/API---copy-to-user.html)という関数を使う必要があります。
しかし、なぜ高い権限のカーネル空間から低い権限のユーザー空間のデータを読み書きできなくするのでしょうか。

私は歴史的な経緯については知りませんが、SMAPによる恩恵は主に2つあると考えます。

まず1つ目が、Stack Pivotの防止です。
SMEPで出した例ではRIPを制御できてもシェルコードは実行できなくなりました。しかし、Linuxカーネルは非常に膨大な量の機械語を持っているため、次のようなROP gadgetが必ず存在します。
```
mov esp, 0x12345678; ret;
```
ESPに入る値が何であれ、このROP gadgetが呼ばれるとRSPはその値に変更されます[^1]。一方、このような低いアドレスはユーザーランドから`mmap`で確保可能ですので、SMEPが有効でも攻撃者はRIPを取るだけで次のようにROP chainを実行できます。
```c
void *p = mmap(0x12345000, 0x1000, ...);
unsigned long *chain = (unsigned long*)(p + 0x678);
*chain++ = rop_pop_rdi;
*chain++ = 0;
*chain++ = ...;
...

control_rip(rop_mov_esp_12345678h);
```
もしSMAPが有効なら、ユーザー空間でmmapしたデータはカーネル空間から見えませんので、stack pivotの後のretの瞬間にカーネルパニックを起こします。
このように、SMEPに加えてSMAPが有効になることで攻撃者がROPを実行するのを困難にできます。

SMAPによる2つ目の恩恵が、カーネルプログラミングで頻出するバグの防止です。
これにはデバイスドライバなどのプログラマが頻繁に起こしてしまうカーネル特有のバグが関係します。`ioctl`というシステムコールでユーザー空間からデバイスドライバとデータをやり取りできるのですが、ドライバが次のようなコードを書いたとしましょう。
```c
char buffer[0x10];

static long mydevice_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  if (cmd == 0xdead) {
    memcpy(buffer, arg, 0x10);
  } else if (cmd == 0xcafe) {
    memcpy(arg, buffer, 0x10);
  }
  return 
}
```
このデバイスドライバはユーザー空間から次のように利用すると、0x10バイトのデータを記憶してくれます。
```c
int fd = open("/dev/mydevice", O_RDWR);

char src[0x10] = "Hello, World!";
char dst[0x10];

ioctl(fd, 0xdead, src);
ioctl(fd, 0xcafe, dst);

printf("%s\n", dst); // --> Hello, World!
```
ユーザー空間のプログラミングに慣れていると何ということはありません。`memcpy`のサイズも固定で、特に問題は無いように思えます。

しかし、もしSMAPが無効だと、次のような呼び出しも許されてしまいます。
```c
ioctl(fd, 0xdead, 0xffffffffdeadbeef);
```
`0xffffffffdeadbeef`というのはユーザー空間としては無効なアドレスですが、仮にこれがLinuxカーネル中の秘密のデータが入っているアドレスだったとしましょう。するとデバイスドライバは
```
memcpy(buffer, 0xffffffffdeadbeef, 0x10);
```
を実行してしまい、秘密のデータを読んでしまいます。今回の例のように何のチェックもなしにユーザー空間から受け取ったアドレスで`memcpy`を使ってしまうと、ユーザー空間からカーネル空間の任意のアドレスを読み書きできてしまうことになります。
カーネルプログラミングに慣れ親しんでいない方にとっては非常に気づきにくい脆弱性ですが、AAR/AAWができるため影響は重大です。このようなミスを防ぐためにもSMAPは役に立っているのです。

SMAPはqemu実行時の引数で有効化できます。次のように`-cpu`オプションに`+smap`と付いていればSMAPが有効化されます。
```
-cpu kvm64,+smap
```
マシン内部からは`/proc/cpuinfo`を見ることでも確認できます。
```
$ cat /proc/cpuinfo | grep smap
```

SMAPもSMEP同様にハードウェアのセキュリティ機構です。CR4レジスタの22ビット目を立てるとSMAPが有効になります。

<div class="balloon_l">
  <div class="faceicon"><img src="../img/cow.jpg" alt="牛さん" ></div>
  <p class="says">
    Intel CPUではEFLAGS.AC (Alignment Check)というフラグをそれぞれ1,0に変更する<a href="https://www.felixcloutier.com/x86/stac" target="_blank">STAC</a>と<a href="https://www.felixcloutier.com/x86/clac" target="_blank">CLAC</a>という命令があって、ACがセットされている間はSMAPの効力が無効になるよ。
  </p>
</div>


## KASLR / FGKASLR
ユーザー空間ではアドレスをランダム化するASLR(Address Space Layout Randomization)が存在しました。これと同様に、Linuxカーネルやデバイスドライバのコード・データ領域のアドレスをランダム化する**KASLR**(Kernel ASLR)という緩和機構も存在します。
カーネルは一度ロードされたら移動しませんので、KASLRは起動時に1度だけ働きます。何か1つでもLinuxカーネル中の関数やデータのアドレスをリークできれば、ベースアドレスが求まります。

[2020年に入ってから](https://lwn.net/Articles/824307/)**FGKASLR**(Function Granular KASLR)と呼ばれるさらに強いKASLRが登場しました。2021年現在はデフォルトで無効なようですが、これはLinuxカーネルの関数ごとにアドレスをランダム化するという技術です。たとえLinuxカーネル中の関数のアドレスがリークできても、ベースアドレスは求まりません。
しかし、FGKASLRはデータセクションなどはランダム化しませんので、データのアドレスをリークできればベースアドレスが求まります。もっともベースアドレスから特定の関数のアドレスを求めることもできませんが、後々登場する特殊な攻撃ベクタには利用可能です。

アドレスはカーネル空間で共通という点に注意してください。たとえあるデバイスドライバがKASLRのおかげでexploit不可能だとしても、何か別のデバイスドライバがカーネルのアドレスをリークしてしまうと、そのアドレスはすべてに適用できます。

KASLRはカーネルの起動時引数で無効化できます。qemuの`-append`オプションに`nokaslr`と付いていればKASLRは無効化されています
```
-append "... nokaslr ..."
```

## KPTI (Kernel Page-Table Isolation)
2018年にIntel等のCPUで[Meltdown](https://ja.wikipedia.org/wiki/Meltdown)と呼ばれるサイドチャネル攻撃が発見されました。この脆弱性については説明しませんが、カーネル空間のメモリをユーザー権限で読めてしまうという重大な脆弱性で、KASLRの回避などが可能でした。近年のLinuxカーネルではMeltdownの対策として、**KPTI**(Kernel Page-Table Isolation)、あるいは古い名称で**KAISER**と呼ばれる機構が有効になっています。

仮想アドレスから物理アドレスに変換する際にページテーブルが利用されるのはご存知の通りですが、このページテーブルをユーザーモードとカーネルモードで分離する[^2]のがこのセキュリティ機構です。KPTIはあくまでMeltdownを防ぐためのセキュリティ機構なので通常のカーネルexploitにおいては問題になりません。しかし、カーネル空間でROPする場合などにKPTIが有効だと、最後にユーザー空間に戻る際に問題が発生します。具体的な解決方法はKernel ROPの章であらためて説明します。

KPTIはカーネルの起動時引数で有効化できます。qemuの`-append`オプションに`pti=on`と付いていればKPTIは有効化され、`pti=off`や`nopti`が付いていれば無効化されます。
```
-append "... pti=on ..."
```
ただし、最近のLinuxカーネルでは固定でKPTIを有効にする場合もあるため、`/sys/devices/system/cpu/vulnerabilities/meltdown`を確認しましょう。次のように「Mitigation: PTI」と書いていればKPTIが有効です。
```
# cat /sys/devices/system/cpu/vulnerabilities/meltdown
Mitigation: PTI
```
無効な場合は「Vulnerable」となります。

KPTIはページテーブルの切り替えなので、CR3レジスタの操作でユーザー・カーネル空間を切り替えられます。LinuxにおいてはCR3に0x1000をORする（すなわちPDBRを変更する）ことでカーネル空間からユーザー空間に切り替わります。この操作は[`swapgs_restore_regs_and_return_to_usermode`](https://github.com/torvalds/linux/blob/master/arch/x86/entry/entry_64.S)で定義されていますが、詳細は実際にexploitを書く章で説明します。

## KADR (Kernel Address Display Restriction)
Linuxカーネルでは、関数の名前とアドレスの情報を`/proc/kallsyms`から読むことができます。また、デバイスドライバによっては`printk`関数などを使い、さまざまなデバッグ情報をログに出力するものもあり、このログは`dmesg`コマンドなどでユーザーから見ることができます。
このように、カーネル空間の関数やデータ、ヒープなどのアドレス情報のリークを防ぐための機構がLinuxには存在します。正式な名称は無いと思いますが、[参考文献](https://inaz2.hatenablog.com/entry/2015/03/27/021422)では**KADR**(Kernel Address Display Restriction)と呼んでいるようなので、このサイトでもその名称を採用します。

この機能は`/proc/sys/kernel/kptr_restrict`の値により変更できます。`kptr_restrict`が0である場合、アドレスの表示に制限はかかりません。`kptr_restrict`が1である場合、`CAP_SYSLOG`権限を持つユーザーにはアドレスが表示されます。`kptr_restrict`が2である場合、ユーザーが特権レベルであってもカーネルアドレスは隠されます。
KADRが無効な場合はアドレスリークの必要がなくなるため、最初に確認するとexploitが簡単になる場合があります。

[^1]: x64では32-bitのレジスタに対して演算する結果が64-bitに拡張されます。
[^2]: システムコールの呼び出しだけはカーネル・ユーザー空間で共有されます。

----

<div class="column" title="例題">
  <a href="../LK01/distfiles/LK01.tar.gz">練習問題LK01</a>のカーネルに対して以下の操作を実行しましょう。（前の例題で既にroot権限のシェルを持っている状態から始めてください。）<br>
  (1) <code>run.sh</code>を読んで、KASLR, KPTI, SMAP, SMEPが有効かどうかを確認してください。<br>
  (2) SMAP, SMEP両方を有効にするオプションを付けて起動し、<code>/proc/cpuinfo</code>を見てSMAP, SMEPが有効になっていることを確認してください。（確認後にSMAP, SMEPは再度無効化してください。）<br>
  (3) 「<code>head /proc/kallsyms</code>」で最初に現れるアドレスはカーネルのベースアドレスです。KASLRが無効の場合、ベースアドレスがいくつになるか確認してください。（ヒント：KADRに注意）
</div>
