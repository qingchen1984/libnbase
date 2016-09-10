#ifndef _SSIGNAL_H
#define _SSIGNAL_H

#include <signal.h>
#include <stdint.h>

typedef struct _ssignal
{
  sigset_t *m_wait_mask;

  int (*block_all_signal)(struct _ssignal *);
  int (*register_quit_signal)(struct _ssignal *, uint32_t);
  int (*event_loop)(struct _ssignal *);
  int (*del_signal)(struct _ssignal **);
} ssignal_t;

ssignal_t *si_init();

int si_block_all_signal(ssignal_t *);

int si_register_quit_signal(ssignal_t *, uint32_t);

int si_event_loop(ssignal_t *);

int si_del_signal(ssignal_t **);

#endif // _SSIGNAL_H
