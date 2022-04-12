---
title: Double Fetch
tags:
    - [Linux]
    - [Kernel]
    - [Data Race]
    - [Double Fetch]
lang: ja
---
LK03(Dexter)ではDouble Fetchと呼ばれる脆弱性について学びます。まず[練習問題LK03](distfiles/LK03.tar.gz)のファイルをダウンロードしてください。

<div class="column" title="目次">
<!-- toc --><br>
</div>

## ソースコードの解析
まずはLK03のソースコードを読んでみましょう。ソースコードは`src/dexter.c`に書かれています。
このプログラムは最大0x20バイトのデータを格納できるカーネルモジュールです。`ioctl`で操作でき、データを読み出す機能と書き込む機能が提供されています。
```c
#define CMD_GET 0xdec50001
#define CMD_SET 0xdec50002
...
  switch (cmd) {
    case CMD_GET: return copy_data_to_user(filp, (void*)arg);
    case CMD_SET: return copy_data_from_user(filp, (void*)arg);
    default: return -EINVAL;
  }
```
デバイスが`open`されると`private_data`に0x20バイトの領域が`kzalloc`で確保されます。この領域はデバイスを`close`すると解放されます。
```c
static int module_open(struct inode *inode, struct file *filp) {
  filp->private_data = kzalloc(BUFFER_SIZE, GFP_KERNEL);
  if (!filp->private_data) return -ENOMEM;
  return 0;
}

static int module_close(struct inode *inode, struct file *filp) {
  kfree(filp->private_data);
  return 0;
}
```
`ioctl`が呼ばれると、`verify_request`でユーザーから渡されるデータを検証します。`verify_request`ではユーザーから受け取ったデータのポインタが非NULLで、かつサイズが0x20を超えていないことを確認しています。
```c
int verify_request(void *reqp) {
  request_t req;
  if (copy_from_user(&req, reqp, sizeof(request_t)))
    return -1;
  if (!req.ptr || req.len > BUFFER_SIZE)
    return -1;
  return 0;
}

...

  if (verify_request((void*)arg))
    return -EINVAL;
```
次にそれぞれ`CMD_GET`, `CMD_SET`では`private_data`からユーザーにデータをコピーしたり、ユーザーから`private_data`にデータをコピーしたりできます。
```c
long copy_data_to_user(struct file *filp, void *reqp) {
  request_t req;
  if (copy_from_user(&req, reqp, sizeof(request_t)))
    return -EINVAL;
  if (copy_to_user(req.ptr, filp->private_data, req.len))
    return -EINVAL;
  return 0;
}

long copy_data_from_user(struct file *filp, void *reqp) {
  request_t req;
  if (copy_from_user(&req, reqp, sizeof(request_t)))
    return -EINVAL;
  if (copy_from_user(filp->private_data, req.ptr, req.len))
    return -EINVAL;
  return 0;
}
```
ユーザーからデータをコピーする前に`verify_request`でサイズを確認しているため、Heap Buffer Overflowは一見存在しないように思えます。

## Double Fetch
**Double Fetch**は、カーネル空間で発生するデータ競合の一種に付けられた名前です。名前の通り、カーネル側で同じデータを2回fetchする（読み込む）ことで発生する競合を指します。
次のように、カーネル空間がユーザー空間から同じデータを2回読むとき、その間に別のスレッドがデータを書き換える可能性があります。

<center>
  <img src="img/double_fetch.png" alt="Double Fetch" style="width:720px;">
</center>

このとき1回目と2回目のfetchでデータ内容が異なるため、整合性が取れなくなります。このようなデータ競合をDouble Fetchと呼びます。

今回のドライバでは、`verify_request`と`copy_data_to_user`/`copy_data_from_user`でユーザーからのリクエストデータをfetchしています。つまり、`verify_request`では正しいサイズを渡し、そこから`copy_data_to_user`あるいは`copy_data_from_user`が実行されるまでの間にサイズ情報を不正な値に書き換えれば、Heap Buffer Oveflowが起こせます。

<div class="balloon_l">
  <div class="faceicon"><img src="../img/cow.jpg" alt="牛さん" ></div>
  <p class="says">
    ユーザー空間のデータを複数回扱うときは、最初にカーネル空間にコピーしたものを使わないとダメなんだね。
  </p>
</div>

## 脆弱性の発火


