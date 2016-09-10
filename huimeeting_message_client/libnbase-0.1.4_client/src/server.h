#ifndef _SERVER_H
#define _SERVER_H

#include "core.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

  /* initialize server struct */
  server_t *server_init();

  void *sv_start_i(void *);

  /* start server */
  void sv_start(server_t *);

  /* stop server */
  void sv_stop(server_t *);

  /* restart server  */
  void sv_restart(server_t *);

  /* handle event call */
  void sv_event_handler(int, short, void*);

  /* initialize server */
  int sv_init(server_t *);

  int sv_listen_sock_tcp(server_t *);

  int sv_listen_sock_udp(server_t *);

  int sv_listen_sock_broadcast(server_t *);

  /* initialize socket */
  int sv_init_socket(server_t *, char *, int, int, int);

  int sv_push_data(server_t *, char *, int, char *, int, int, int);

  int sv_terminate_node(server_t *, char *, int, int, int);

  void sv_message_echo_all(server_t *, char *, int);

  void sv_message_echo_tcp(server_t *, char *, int, char *);

  /* run server */
  void sv_run(server_t *);

  /* add new connection to threads */
  int sv_addconn(server_t *, int, int, struct sockaddr_in *);

  /* terminate sv */
  void sv_terminate(server_t *);

  /* clean sv */
  void sv_clean(server_t **);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _SERVER_H
