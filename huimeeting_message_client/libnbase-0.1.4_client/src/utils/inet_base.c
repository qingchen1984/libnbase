#include "inet_base.h"
#include "timer.h"

int inet_init(int fd, struct sockaddr_in *sa, int backlog, int flag)
{
#define RET_CHECK(_ret) if(_ret != 0) return -1;
  /*
     int fd 	= 0;
     SOCK_NEW(fd, domain, type, family);	
     if(fd < 0)
     return -1;

     struct sockaddr_in sa;
  //SA_SET(sa, domain, ip, port);
  SA_SET(sa, domain, sock_t, is_broadcast, port);
  */

  int ret = 0;
  //bind fd and socket
  if (flag & S_SOCK_BIND) {
    SOCK_BIND(fd, (*sa), ret);
    RET_CHECK(ret);
  }

  //connect to remote host
  if (flag & S_SOCK_CONN) {
    SOCK_CONN(fd, (*sa), ret);
    RET_CHECK(ret);
  }

  //set NONLOCK	
  if (flag & S_SOCK_NONBLOCK) {
    SOCK_NONBLOCK(fd, ret);
    RET_CHECK(ret);
  }

  //listen
  if (flag & S_SOCK_LISTEN) {
    SOCK_LISTEN(fd, backlog, ret);
    RET_CHECK(ret);
  }
  return ret;
}

/* read data from socket fd */
int inet_read(int fd, char *buf, int len, suseconds_t timeout)
{
  int n = 0, total = -1, recv = len;
  char *p = buf;
  base_timer_t *timer = timer_init();

  while (timer && total < len) {
    if ((n = read(fd, p, recv)) > 0) {
      total += n;
      p += n;
      recv -= n;
    }
    timer->sample(timer);
    if (timer->usec_used >= timeout) {
      goto end;
    }
    usleep(10);
  }
end:
  {
    if (timer)
      timer->clean(&timer);
  }
  return total;
}

/* write data to socket fd */
int inet_write(int fd, char *buf, int len, suseconds_t timeout)
{
  int n = 0, total = -1, sent = len;
  char *p = buf;
  base_timer_t *timer = timer_init();

  while (timer && total < len) {
    if ((n = write(fd, p, sent)) > 0) {
      total += n;
      p += n;
      sent -= n;
    }
    timer->sample(timer);
    if (timer->usec_used >= timeout) {
      goto end;
    }
    usleep(10);
  }
end:
  {
    if (timer)
      timer->clean(&timer);
  }
  return total;
}

/*
#ifdef DEBUG_TEST
int main(int argc, char **argv)
{
  if (argc < 4) {
    ERROR_LOG("Usage:%s host port msg\n", argv[0]);
    return -1;
  }
  char *host = argv[1];
  int port = atoi(argv[2]);
  int fd = inet_init(AF_INET, SOCK_DGRAM, 0, host, port, 0,
      S_SOCK_CONN | S_SOCK_NONBLOCK);

  int len = 0;
  char *msg = argv[3];
  int msglen = strlen(msg) + 1;
  if ((len = write(fd, msg, msglen)) > 0) {
    DEBUG_LOG(__FILE__, __LINE__, "WRITE:%d\n", len);
  }

  char buf[8192];
  while (1) {
    fgets(buf, 8192, stdin);
    len = strlen(buf);
    if (len > 0)
      write(fd, buf, len + 1);
    if(fd < 0 )
      break;
    if ((len = inet_read(fd, buf, 8192)) > 0)
      fprintf(stdout, "data:%s\n", buf);
    sleep(1);
  }
  close(fd);
  return 0;
}
#endif
*/
