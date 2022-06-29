---
title: FUSEの利用
tags:
    - [Linux]
    - [Kernel]
    - [Race Condition]
    - [Data Race]
    - [FUSE]
lang: ja
---
[前章](uffd.html)ではuserfaultfdを利用してLK04(Fleckvieh)の競合を安定化させました。本章では同じくLK04を、別の方法でexploitしてみます。

<div class="column" title="目次">
<!-- toc --><br>
</div>

## userfaultfdの欠点
前章でも少し説明したように、userfaultfdは現在のLinuxでは標準で一般ユーザーは利用できません。正確には、ユーザー空間で発生さしたページフォルトは検知できますが、カーネル空間で発生したものは一般ユーザーの作ったuserfaultfdでは検知できません。それぞれ以下のパッチで導入されたセキュリティ緩和機構です。

- [userfaultfd: allow to forbid unprivileged users](https://lwn.net/Articles/782745/)
- [Control over userfaultfd kernel-fault handling](https://lwn.net/Articles/835373/)

そこで、今回はLinuxの機能の一つであるFUSEという仕組みを利用します。まずはFUSEとは何かを勉強しましょう。

## FUSEとは
[**FUSE**(Filesystem in Userspace)](https://lwn.net/Articles/68104/)は、ユーザー空間から仮想的にファイルシステムの実装を可能にするLinuxの機能です。`CONFIG_FUSE_FS`を付けてカーネルをビルドすると有効になります。
まず、プログラムはFUSEを使ってファイルシステムをマウントします。誰かがこのファイルシステム中のファイルにアクセスすると、プログラム側で設定したハンドラが呼び出されます。構造はLK01で見たキャラクターデバイスの実装と非常に似ています[^1]。

## FUSEの利用
システム上のFUSEのバージョンは`fusermount`コマンドで調査できます。
```
/ $ fusermount -V
fusermount version: 2.9.9
```
ローカルマシンでFUSEを試したい場合、次のコマンドでインストールしてください。今回はターゲットのFUSEがバージョン2なので、fuse3ではなくfuseを使います。
```
# apt-get install fuse
```
また、FUSEを使うプログラムをコンパイルする上でヘッダが必要になるので、次のコマンドでインストールしておいてください。
```
# apt-get install libfuse-dev
```

それでは実際にFUSEを使ってみましょう。
FUSEを利用して作ったファイルシステム中のファイルに操作が走ると、`fuse_operations`に定義したハンドラが呼び出されます。`fuse_operations`にはファイル操作の`open`, `read`, `write`, `close`やディレクトリアクセスの`readdir`, `mkdir`などの他、`chmod`や`ioctl`, `poll`など、あらゆる操作を独自実装できます。今回はexploitの目的で利用するだけなので、ファイルの`open`, `read`が実装できれば十分です。また、`open`するためにはファイルの権限などの情報を返す`getattr`関数も定義する必要があります。実際のコードを読んでみましょう。
```c
#define FUSE_USE_VERSION 29
#include <errno.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>

static const char *content = "Hello, World!\n";

static int getattr_callback(const char *path, struct stat *stbuf) {
  puts("[+] getattr_callback");
  memset(stbuf, 0, sizeof(struct stat));

  /* マウント箇所からみたパスが"/file"かを確認 */
  if (strcmp(path, "/file") == 0) {
    stbuf->st_mode = S_IFREG | 0777; // 権限
    stbuf->st_nlink = 1; // ハードリンクの数
    stbuf->st_size = strlen(content); // ファイルサイズ
    return 0;
  }

  return -ENOENT;
}

static int open_callback(const char *path, struct fuse_file_info *fi) {
  puts("[+] open_callback");
  return 0;
}

static int read_callback(const char *path,
                         char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi) {
  puts("[+] read_callback");

  if (strcmp(path, "/file") == 0) {
    size_t len = strlen(content);
    if (offset >= len) return 0;

    /* データを返す */
    if ((size > len) || (offset + size > len)) {
      memcpy(buf, content + offset, len - offset);
      return len - offset;
    } else {
      memcpy(buf, content + offset, size);
      return size;
    }
  }

  return -ENOENT;
}

static struct fuse_operations fops = {
  .getattr = getattr_callback,
  .open = open_callback,
  .read = read_callback,
};

int main(int argc, char *argv[]) {
  return fuse_main(argc, argv, &fops, NULL);
}
```
次のように`-D_FILE_OFFSET_BITS=64`を付けてコンパイルします。
```
$ gcc test.c -o test -D_FILE_OFFSET_BITS=64 -lfuse
```
`fuse_main`が引数をパースしてメイン処理を実行します。ここでは`/tmp/test`にマウントしてみます。
```
$ mkdir /tmp/test
$ ./test -f /tmp/test
```
正しく動作している場合、エラーは出ずにプログラムが停止します。エラーが出る場合、OSがFUSEに対応しているかや、コンパイル時のFUSEのバージョンが一致しているかなどを確認してください。
この状態で別のターミナルから`/tmp/test/file`にアクセスすると、データが読めるはずです。
```
$ cat /tmp/test/file
Hello, World!
```
なお、今回は`readdir`を実装していないため、マウントポイントに対して`ls`などでファイル一覧を見られない他、ルートディレクトリに対する`getattr`も実装していないため、`/tmp/test`の存在自体が見えなくなっています。

また、上記プログラムで利用している`fuse_main`はヘルパー関数です。いちいち引数を指定するのが嫌な場合は、次のように呼び出すことも可能です。
```c
int main()
{
  struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
  struct fuse_chan *chan;
  struct fuse *fuse;

  if (!(chan = fuse_mount("/tmp/test3", &args)))
    fatal("fuse_mount");

  if (!(fuse = fuse_new(chan, &args, &fops, sizeof(fops), NULL))) {
    fuse_unmount("/tmp/test", chan);
    fatal("fuse_new");
  }

  fuse_set_signal_handlers(fuse_get_session(fuse));
  fuse_loop_mt(fuse);

  fuse_unmount("/tmp/test3", chan);

  return 0;
}
```
`fuse_mount`でマウントポイントを決め、`fuse_new`でFUSEのインスタンスを作成します。`fuse_loop_mt`（`mt`はマルチスレッド）でイベントを監視します。プログラムが終了する際に監視から抜け出せるように、`fuse_set_signal_handlers`を設定するのを忘れないようにしましょう。最後の`fuse_unmount`に到達しないと、マウントポイントが壊れてしまいます。


## Raceの安定化
それではFUSEをexploitの安定化に利用する方法を考えてみましょう。
といっても原理はuserfaultfdの時とまったく同じです。userfaultfdではページフォルトを起点としてユーザー側のハンドラを呼ばせましたが、FUSEの場合はファイルのreadを起点とします。
FUSEで実装したファイルを`mmap`で`MAP_POPULATE`なしでメモリにマップすると、その領域を読み書きした時点でページフォルトが発生し、最終的に`read`が呼び出されます。これを利用すればuserfaultfdのときと同じように、メモリ読み書きが発生するタイミングでコンテキストを切り替えられます。

図で表すと次のようになります。

<center>
  <img src="img/fuse_uafr.png" alt="FUSEによるUse-after-Free" style="width:720px;">
</center>



---

[^1]: ユーザー空間で仮想的にキャラクタデバイスを登録するCUSEという仕組みもあります。
[^2]: 
