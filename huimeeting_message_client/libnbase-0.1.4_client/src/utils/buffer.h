#ifndef _BUFFER_H
#define _BUFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct _buffer
{
  void *data;
  void *end;
  size_t size;

  pthread_mutex_t mutex;

  void *(*calloc)(struct _buffer *, size_t);
  void *(*malloc)(struct _buffer *, size_t);
  void *(*recalloc)(struct _buffer *, size_t);
  void *(*remalloc)(struct _buffer *, size_t);
  int (*push)(struct _buffer *, void *, size_t);
  int (*del)(struct _buffer *, size_t);
  void (*reset)(struct _buffer *);
  void (*clean)(struct _buffer **);

} buffer_t;

#define BUFFER_VIEW(buf) \
  { \
    if(buf) { \
      fprintf(stdout, "buf:%08X\n" \
          "buf->data:%08X\n" \
          "buf->end:%08X\n" \
          "buf->size:%ld\n" \
          "buf->recalloc():%08X\n" \
          "buf->remalloc():%08X\n" \
          "buf->push():%08X\n" \
          "buf->del():%08X\n" \
          "buf->reset():%08X\n" \
          "buf->clean():%08X\n", \
          buf, buf->data, buf->end, buf->size, \
          buf->recalloc, buf->remalloc, \
          buf->push, buf->del, \
          buf->reset, buf->clean); \
    } \
  }

buffer_t *buffer_init();

/* calloc memory at end of buffer */
void* buf_calloc(buffer_t *, size_t);

/* malloc memory at end of buffer */
void* buf_malloc(buffer_t *, size_t);

/* recalloc memory */
void* buf_recalloc(buffer_t *, size_t);

/* remalloc memory */
void* buf_remalloc(buffer_t *, size_t);

/* push data to buffer tail */
int buf_push(buffer_t *, void *, size_t);

/* delete data from buffer */
int buf_del(buffer_t *, size_t);

/* reset buffer */
void buf_reset(buffer_t *);

/* clean and free */
void buf_clean(buffer_t **);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _BUFFER_H
