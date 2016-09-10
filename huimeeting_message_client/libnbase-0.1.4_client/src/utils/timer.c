#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "timer.h"

/* initialize timer */
base_timer_t *timer_init()
{
  base_timer_t *timer = (base_timer_t *) calloc(1, sizeof(base_timer_t));
  if (timer) {
    gettimeofday(&(timer->tv), NULL);
    timer->start_sec = timer->tv.tv_sec;
    timer->start_usec = timer->tv.tv_sec * 1000000llu
        + timer->tv.tv_usec * 1llu;
    timer->last_sec = timer->start_sec;
    timer->last_usec = timer->start_usec;
    timer->sample = timer_sample;
    timer->reset = timer_reset;
    timer->check = timer_check;
    timer->clean = timer_clean;
    pthread_mutex_init(&(timer->mutex), NULL);
  }
  return timer;
}

/* reset timer */
void timer_reset(base_timer_t *timer)
{
  if (timer) {
    pthread_mutex_lock(&(timer->mutex));
    gettimeofday(&(timer->tv), NULL);
    timer->start_sec = timer->tv.tv_sec;
    timer->start_usec = timer->tv.tv_sec * 1000000llu
        + timer->tv.tv_usec * 1llu;
    timer->last_sec = timer->start_sec;
    timer->last_usec = timer->start_usec;
    pthread_mutex_unlock(&(timer->mutex));
  }
}

/* timer sample */
void timer_sample(base_timer_t *timer)
{
  if (timer) {
    pthread_mutex_lock(&(timer->mutex));
    gettimeofday(&(timer->tv), NULL);
    timer->last_sec_used = timer->tv.tv_sec - timer->last_sec;
    timer->last_usec_used = timer->tv.tv_sec * 1000000llu + timer->tv.tv_usec
        - timer->last_usec;
    timer->last_sec = timer->tv.tv_sec;
    timer->last_usec = timer->tv.tv_sec * 1000000llu + timer->tv.tv_usec;
    timer->sec_used = timer->tv.tv_sec - timer->start_sec;
    timer->usec_used = timer->last_usec - timer->start_usec;
    pthread_mutex_unlock(&(timer->mutex));
  }
}

/* check timer and run callback */
void timer_check(base_timer_t *timer, uint32_t interval)
{
  uint64_t n = 0llu;
  if (timer) {
    pthread_mutex_lock(&(timer->mutex));
    gettimeofday(&(timer->tv), NULL);
    n = (timer->tv.tv_sec * 1000000llu + timer->tv.tv_usec);
    if ((n - timer->last_usec) >= interval && timer->callback) {
      timer->callback();
      timer->last_sec_used = timer->tv.tv_sec - timer->last_sec;
      timer->last_usec_used = n - timer->last_usec;
      timer->last_sec = timer->tv.tv_sec;
      timer->last_usec = n;
      timer->sec_used = timer->tv.tv_sec - timer->start_sec;
      timer->usec_used = timer->last_usec - timer->start_usec;
    }
    pthread_mutex_unlock(&(timer->mutex));
  }
}

/* clean timer */
void timer_clean(base_timer_t **timer)
{
  if ((*timer))
    free((*timer));
  (*timer) = NULL;
}

/* heartbeat */
void heartbeat()
{
  printf("heartbeat testing \n");
}

/* timer testing */
#ifdef _DEBUG_TIMER
int main()
{
  int i = 10000;
  uint32_t interval = 10000000u;
  base_timer_t *timer = timer_init();
  timer->callback = &heartbeat;

  while (i--) {
    timer->check(timer, interval);
    usleep(1000);
  }
  timer->clean(&timer);
}
#endif // _DEBUG_TIMER
