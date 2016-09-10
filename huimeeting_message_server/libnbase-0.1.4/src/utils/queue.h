#ifndef _QUEUE_H
#define _QUEUE_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

  typedef struct _queue_elem
  {
    void *data;
    struct _queue_elem *next;
  } queue_elem_t;

  typedef struct _queue
  {
    queue_elem_t *first;
    queue_elem_t *last;
    size_t total;

    pthread_mutex_t mutex;

    void (*push)(struct _queue *, void *);
    void* (*pop)(struct _queue *);
    void (*del)(struct _queue *);
    void* (*head)(struct _queue *);
    void* (*tail)(struct _queue *);
    void (*clean)(struct _queue **);

  } queue_t;

  /* initialize queue */
  queue_t *queue_init();

  /* push queue_elem to queue tail */
  void queue_push(queue_t *, void *);

  /* pop queue_elem data from queue head and free it */
  void *queue_pop(queue_t *);

  /* delete queue_elem data from queue head and free it */
  void queue_del(queue_t *);

  /* get queue head data don't free */
  void *queue_head(queue_t *);

  /* get queue tail data don't free */
  void *queue_tail(queue_t *);

  /* clean queue */
  void queue_clean(queue_t **);

#define QUEUE_VIEW(queue) \
  { \
    if(queue) { \
      fprintf(stdout, "queue:%08X\n" \
          "queue->first:%08X\n" \
          "queue->last:%08X\n" \
          "queue->total:%u\n" \
          "queue->push():%08X\n" \
          "queue->pop():%08X\n" \
          "queue->head():%08X\n" \
          "queue->tail()::%08X\n" \
          "queue->clean():%08X\n", \
          queue, queue->first, queue->last, \
          queue->total, queue->push, queue->pop, \
          queue->head, queue->tail, queue->clean); \
    } \
  } 

#define QUEUE_INIT() \
  { \
    queue_t *queue = (queue_t *)calloc(1, sizeof(queue_t)); \
    if(queue) { \
      queue->push	= queue_push; \
      queue->pop = queue_pop; \
      queue->head	= queue_head; \
      queue->tail	= queue_tail; \
      queue->clean = queue_clean; \
    } \
    return(queue); \
  }

#define QUEUE_PUSH(queue, data) \
  { \
    if(queue) { \
      if(queue->last) { \
        queue->last->next = (queue_elem_t *)calloc(1, sizeof(queue_elem_t)); \
        queue->last = queue->last->next; \
      }	else { \
        queue->last = (queue_elem_t *)calloc(1, sizeof(queue_elem_t)); \
        if(queue->first == NULL) queue->first = queue->last; \
      } \
      queue->last->data = data; \
      queue->total++; \
    }	\
  }

#define QUEUE_POP(queue) \
  { \
    void *p = NULL; \
    queue_elem_t *elem = NULL; \
    if(queue) { \
      if(queue->first) { \
        elem = queue->fist; \
        if(queue->fist == queue->last) { \
          queue->fist = queue->last = NULL; \
        } else { \
          queue->first = queue->first->next; \
        } \
        p = elem->data; \
        free(elem); \
      } \
    } \
    return(p); \
  } 

#define QUEUE_HEAD(queue) \
  { \
    void *p = NULL; \
    if(queue && queue->fist) { \
      p = queue->fist->data; \
    } \
    return(p); \
  } 

#define QUEUE_TAIL(queue) \
  { \
    void *p = NULL; \
    if(queue && queue->last) { \
      p = queue->last->data; \
    } \
    return(p); \
  } 

#define QUEUE_CLEAN(queue) \
  { \
    queue_elem_t *elem = NULL, p = NULL; \
    if(queue) { \
      p = elem = queue->first; \
      while(elem != queue_last->last) { \
        elem = elem->next; \
        free(p); \
        p = elem; \
      } \
      free(queue); \
    } \
  }

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _QUEUE_H
