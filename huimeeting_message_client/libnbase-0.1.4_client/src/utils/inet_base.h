#ifndef INET_BASE_H
#define INET_BASE_H

#include <netdb.h>
#include <netinet/in.h>
#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifndef _ERROR_LOG
#define _ERROR_LOG(format...) \
  { \
    fprintf(stderr, "[%s:%d] ", __FILE__, __LINE__); \
    fprintf(stderr, "\""); \
    fprintf(stderr, format); \
    fprintf(stderr, "\""); \
    fprintf(stderr, "\n"); \
  }
#endif // _ERROR_LOG

#ifndef _DEBUG_LOG
#ifdef  _DEBUG
#define _DEBUG_LOG(format...) \
  { \
    fprintf(stdout, "[%s:%d] ", __FILE__, __LINE__); \
    fprintf(stdout, "\""); \
    fprintf(stdout, format); \
    fprintf(stdout, "\""); \
    fprintf(stdout, "\n"); \
  }
#else // _DEBUG
#define _DEBUG_LOG(format...)
#endif // _DEBUG
#endif // _DEBUG_LOG

#define S_SOCK_BIND	0x01
#define S_SOCK_CONN	0x04
#define S_SOCK_NONBLOCK	0x08
#define S_SOCK_LISTEN	0x10

typedef struct _socknode
{
  char ip[64];
  int port;
} socknode_t;

#ifndef INT2IP
/**
 * convert 32 bits number to ip string
 * @_num: 32 bits number
 * @_ip: ip string delimited with dot
 */
#define INT2IP(_num, _ip) \
{ \
  uint32_t _p1, _p2, _p3, _p4 , _n; \
  _p4 = _num & 0xFF; \
  _p3 = (_num >> 8) & 0xFF; \
  _p2 = (_num >> 16) & 0xFF; \
  _p1 = (_num >> 24) & 0xFF; \
  _n = sprintf(_ip, "%d.%d.%d.%d", _p1, _p2, _p3, _p4); \
  _ip[_n] = '\0'; \
}
#endif // INT2IP

#ifndef IP2INT
/**
 * convert ip string to 32 bits number
 * @_ip: ip string
 * @_num: 32 bits number
 */
#define IP2INT(_ip, _num) \
{ \
  uint32_t _p1, _p2, _p3, _p4; \
  int _n; \
  _num = 0; \
  _n = sscanf(_ip, "%d.%d.%d.%d", &_p1, &_p2, &_p3, &_p4); \
  if (_n == 4) \
  _num = (_p1 << 24) + (_p2 << 16) + (_p3 << 8) + _p4; \
}
#endif // IP2INT

#ifndef HOST2IP
/**
 * get ip as given _host 
 * @_host: hostname
 * @_ip: ip string
 */
#define HOST2IP(_host, _ip) \
{ \
  struct hostent *_hostent = gethostbyname(_host); \
  if (_hostent != NULL) { \
    int _sip = *((int *)_hostent->h_addr_list[0]); \
    INT2IP(_sip, _ip); \
  } \
}
#endif // HOST2IP

#ifndef SN_SET
/**
 * initialize socknode
 * @sn: struct socknode
 * @ip: host ip as string, max length is 64
 * @port: host port with type int
 */
#define SN_SET(_sn, _ip, _port) \
{ \
  _sn.port = port; \
  char *_s = _ip; \
  while (*_s != 0) \
  *(_sn.ip++) = *_s++; \
  *(_sn.ip) = 0 \
}
#endif // SN_SET

#ifndef SA_SET
/**
 * initialize sockaddr_in
 * @sa: struct sockaddr_in
 * @ip: host ip as string, max length is 64
 * @port: host port with type int
 */
#define SA_SET(_sa, _family, _sock_t, _is_broadcast, _port) \
{ \
  memset(&_sa, 0, sizeof(_sa)); \
  _sa.sin_family = _family; \
  _sa.sin_addr.s_addr = htonl(INADDR_ANY); \
  _sa.sin_port = htons(_port); \
}
#endif // SA_SET

#ifndef SA2SA
/**
 * convert struct socknode to sockaddr_in
 * @sn: struct socknode 
 * @sa: struct sockaddr_in 
 */
#define SN2SA(_sn, _sa) \
{ \
  _sa.sin_addr.s_addr = inet_addr(_sn.ip); \
  _sa.sin_port = htons(_sa.port); \
}
#endif // SA2SA

#ifndef SA2SN
/**
 * convert struct sockaddr_in to struct sockaddr_in
 * @sa: struct sockaddr_in
 * @sn: struct socknode
 */
#define SA2SN(_sa, _sn) \
{ \
  SN_SET(_sn, inet_ntoa(_sa.sin_addr), ntohs(_sa.sin_port)); \
}
#endif // SA2SN

#ifndef SOCK_NEW
/**
 * create new socket as given @_domain @_type @_family 
 * @_fd: new socket fd
 * @_domain: same with @domain in socket(@domain, @type, @family);
 * @_type: same with @type in socket(@domain, @type, @family);
 * @_family: same with @family in socket(@domain, @type, @family);
 *
 */
#define SOCK_NEW(_fd, _domain, _type, _family) \
{ \
  _fd = socket(_domain, _type, _family); \
  if (_fd < 0 ) { \
    _ERROR_LOG("error:socket initialized failed, %s", strerror(errno)); \
  } else { \
    _DEBUG_LOG("initialized socket[%d]", _fd); \
  } \
}
#endif // SOCK_NEW

#ifndef SOCK_BIND
/**
 * bind @_fd and @_sa
 * @_fd: socket fd
 * @_sa: pointer of struct sockaddr_in
 */
#define SOCK_BIND(_fd, _sa, _ret) \
{ \
  int _sa_len = sizeof(_sa); \
  int _opt = 1; \
  setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, \
      (char *)&_opt, (socklen_t) sizeof(_opt)); \
  if ((_ret = bind(_fd, (struct sockaddr *)&_sa, _sa_len )) != 0 ) { \
    _ERROR_LOG("error:socket bind failed, %s", strerror(errno)); \
  } else { \
    _DEBUG_LOG("binded socket[%d]", _fd); \
  } \
}
#endif // SOCK_BIND

#ifndef SOCK_CONN
/**
 * connect remote socket @_sa via @_fd
 * @_fd: socket fd
 * @_sa: description of remote socket
 */
#define SOCK_CONN(_fd, _sa, _ret) \
{ \
  int _sa_len = sizeof(_sa); \
  if ((_ret = connect(_fd, (struct sockaddr *)&_sa, _sa_len )) != 0 ) { \
    _ERROR_LOG("error:socket connect failed, %s", strerror(errno)); \
  } else { \
    _DEBUG_LOG("socket[%d] connected %s:%d", \
        _fd, inet_ntoa(_sa.sin_addr), ntohs(_sa.sin_port)); \
  } \
}
#endif // SOCK_CONN

#ifndef SOCK_NONBLOCK
/**
 * set @_fd  as nonblock
 * @_fd: socket  fd 
 */
#define SOCK_NONBLOCK(_fd, _ret) \
{ \
  if ((_ret = fcntl(_fd, F_SETFL, O_NONBLOCK)) != 0) { \
    _ERROR_LOG("error:set fd nonblock failed, %s", strerror(errno)); \
  } else { \
    _DEBUG_LOG("set socket[%d] nonblock ", _fd); \
  } \
}
#endif // SOCK_NONBLOCK

#ifndef SOCK_LISTEN
/**
 * listen socket on @_fd
 * @_fd: socket fd
 * @_backlog: same as @backlog in listen(@fd, @backlog)
 */
#define SOCK_LISTEN(_fd, _backlog, _ret) \
{ \
  if ((_ret = listen(_fd, _backlog)) != 0) { \
    _ERROR_LOG("error:socket listenning failed, %s", strerror(errno)); \
  } else { \
    _DEBUG_LOG("listen socket[%d]", _fd); \
  } \
}
#endif // SOCK_LISTEN

/**
 * initialize the inet socket
 * @fd: socket filedescr
 * @sa: struct sockaddr_in pointer
 * @domain: the same to socket(int domain, int type, int family)'s domain
 * @type: the same to socket(int domain, int type, int family)'s type
 * @family: the same to socket(int domain, int type, int family)'s family, default set it 0 please
 * @ip: host ip string with dot as delimiter, if use all the network interface set is null
 * @backlog: the same to backlog of function listen(int, sockaddr*, int backlog)
 * @flag: whether set socket as listen socket, if 1 for listening, 0 not, default 0
 */
int inet_init(int fd, struct sockaddr_in *sa, int backlog, int flag);

/* read data from socket fd */
int inet_read(int fd, char *buf, int len, suseconds_t timeout);

/* write data to socket fd */
int inet_write(int fd, char *buf, int len, suseconds_t timeout);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // INET_BASE_H
