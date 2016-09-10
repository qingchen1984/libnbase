#ifndef _SESSION_H
#define _SESSION_H

#include "core.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

  /* initialize session struct */
  session_t *session_init();

  /* initialize session */
  int sess_set(session_t *, int, int, struct sockaddr_in *);

  /* session event handler */
  void sess_event_handler(int, short, void *);

  /* update event base*/
  int sess_event_update(session_t *, short);

  /* read data from fd*/
  int sess_read_handler(session_t *);

  /* wirite data to fd */
  int sess_write_handler(session_t *);

  /* push message to pthread joblist queue */
  void sess_push_message(session_t *, int);

  /* add mem_chunk to send queue */
  int sess_push_chunk(session_t *, void *, size_t);

  /* add file_chunk to send queue */
  int sess_push_file(session_t *, char *, uint64_t, uint64_t);

  /* check connection state send oob data ensure connection is connected */
  int sess_state_handler(session_t *);

  /* terminate session */
  int sess_terminate(session_t *);

  /* clean session */
  void sess_clean(session_t **);

  int sess_parse_packet(session_t *);

  int sess_parse_packet_wan(session_t *);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _SESSION_H
