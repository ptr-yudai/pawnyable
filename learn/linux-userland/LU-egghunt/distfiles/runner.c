#include <assert.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <unistd.h>

#define SIZE_DATA 0x4000

void randomize_heap() {
  void *p;
  unsigned short n, size;

  assert (getrandom(&n, sizeof(n), 0) == sizeof(n));
  n %= 0x1000;

  for (int i = 0; i < n; i++) {
    assert (getrandom(&size, sizeof(size), 0) == sizeof(size));
    size %= 0x1000;

    p = malloc(size);
    assert (p != NULL);
    getrandom(p, size, 0);
  }
}

int main() {
  char *data;
  void (*shellcode)() = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  assert (shellcode != MAP_FAILED);

  randomize_heap();

  data = (char*)malloc(SIZE_DATA);
  assert (data != NULL);
  write(STDOUT_FILENO, "data: ", 6);
  read(STDIN_FILENO, data, SIZE_DATA);

  randomize_heap();

  write(STDOUT_FILENO, "shellcode: ", 12);
  read(STDIN_FILENO, shellcode, 0x100);
  shellcode();

  return 0;
}
