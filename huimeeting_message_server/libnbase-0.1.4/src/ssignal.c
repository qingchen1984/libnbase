#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "ssignal.h"

ssignal_t *si_init()
{
  ssignal_t *si = (ssignal_t *) calloc(1, sizeof(ssignal_t));

  si->m_wait_mask = (sigset_t *) calloc(1, sizeof(sigset_t));
  si->block_all_signal = si_block_all_signal;
  si->register_quit_signal = si_register_quit_signal;
  si->event_loop = si_event_loop;
  si->del_signal = si_del_signal;

  return si;
}

int si_block_all_signal(ssignal_t *si)
{
  sigset_t all_mask;
  sigfillset(&all_mask);
  return pthread_sigmask(SIG_BLOCK, &all_mask, NULL);
}

int si_register_quit_signal(ssignal_t *si, uint32_t signal_num_)
{
  sigaddset(si->m_wait_mask, signal_num_);
  return 0;
}

int si_event_loop(ssignal_t *si)
{
  pthread_sigmask(SIG_BLOCK, si->m_wait_mask, NULL);

  int sig_num = 0;
  while (!sigwait(si->m_wait_mask, &sig_num)) {
    return 0;
  }
  return 0;
}

int si_del_signal(ssignal_t **si)
{
  free((*si)->m_wait_mask);
  (*si)->m_wait_mask = NULL;

  free(*si);
  *si = NULL;

  return 0;
}
