#ifndef _THREAD_H
#define _THREAD_H

#include "core.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

  /* initialize thread struct */
  thread_t *thread_init();

  /* thread event handler */
  void pth_event_handler(int, short, void *);

  /* run thread */
  void* pth_run(void *);

  /* add new connection to thread */
  int pth_addconn(thread_t *, int, int, struct sockaddr_in *);

  /* check connection stats */
  void pth_state_conns(thread_t *);

  /* add new session to thread */
  int pth_add_session(thread_t *, int, int, struct sockaddr_in *);

  int pth_push_data(thread_t *, int, char *, int);

  /* terminate session */
  void pth_terminate_session(thread_t *, session_t *);

  /* terminate  thread */
  void pth_terminate(thread_t *);

  /* clean thread child struct */
  void pth_clean(thread_t **);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _THREAD_H
