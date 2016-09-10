#ifndef _TIMER_H
#define _TIMER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _TYPEDEF_TIMER
#define _TYPEDEF_TIMER
typedef struct _base_timer
{
  struct timeval tv;

  time_t start_sec;
  uint64_t start_usec;
  time_t sec_used;
  uint64_t usec_used;
  time_t last_sec;
  uint64_t last_usec;
  time_t last_sec_used;
  uint64_t last_usec_used;

  pthread_mutex_t mutex;

  void (*reset)(struct _base_timer *);
  void (*check)(struct _base_timer *, uint32_t);
  void (*sample)(struct _base_timer *);
  void (*clean)(struct _base_timer **);
  void (*callback)(void);

} base_timer_t;

/* initialize timer */
base_timer_t *timer_init();

#endif // _TYPEDEF_TIMER

/* reset timer */
void timer_reset(base_timer_t *);

/* check timer and run callback */
void timer_check(base_timer_t *, uint32_t);

/* timer gettime */
void timer_sample(base_timer_t *);

/* clean timer */
void timer_clean(base_timer_t **);

/* view timer */
#define TIMER_VIEW(_timer) \
  { \
    if(_timer) \
    { \
      printf("timerptr:%08x\n" \
          "timer->start_sec:%u\n" \
          "timer->start_usec:%llu\n" \
          "timer->tv.tv_sec:%u\n" \
          "timer->tv.tv_usec:%u\n" \
          "timer->sec_used:%u\n" \
          "timer->usec_used:%llu\n" \
          "timer->last_sec:%u\n" \
          "timer->last_usec:%llu\n" \
          "timer->last_sec_used:%u\n" \
          "timer->last_usec_used:%llu\n" \
          "timer->reset():%08x\n" \
          "timer->check():%08x\n" \
          "timer->sample():%08x\n" \
          "timer->clean():%08x\n\n", \
          _timer, \
          _timer->start_sec, \
          _timer->start_usec, \
          _timer->tv.tv_sec, \
          _timer->tv.tv_usec, \
          _timer->sec_used, \
      _timer->usec_used, \
      _timer->last_sec, \
      _timer->last_usec, \
      _timer->last_sec_used, \
      _timer->last_usec_used, \
      _timer->reset, \
      _timer->check, \
      _timer->sample, \
      _timer->clean); \
    } \
  }

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _TIMER_H
