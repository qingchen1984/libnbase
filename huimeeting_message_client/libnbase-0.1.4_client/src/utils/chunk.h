#ifndef _CHUNK_H
#define _CHUNK_H

#include <netdb.h>
#include <netinet/in.h>
#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

  /* chunk */
#ifndef _TYPEDEF_CHUNK
#define _TYPEDEF_CHUNK
#define MEM_CHUNK 0x02
#define FILE_CHUNK 0x04
#define ALL_CHUNK (MEM_CHUNK | FILE_CHUNK)
#define FILE_NAME_LIMIT 255 

  typedef struct _chunk
  {
    /* property */
    int id;
    int type;
    buffer_t *buf;
    struct
    {
      int fd;
      char name[FILE_NAME_LIMIT + 1];
    } file;
    //uint64_t offset;
    //uint64_t len;
    unsigned int offset;
    unsigned int len;

    pthread_mutex_t mutex;

    /* method */
    int (*set)(struct _chunk *, int, int, char *, uint64_t, uint64_t);
    int (*append_tcp)(struct _chunk *, void *, size_t);
    int (*append_tcp_wan)(struct _chunk *, void *, size_t);
    int (*append_udp)(struct _chunk *, void *, size_t);
    int (*fill)(struct _chunk *, void *, size_t);
    int (*send)(struct _chunk *, int, size_t);
    int (*sendto)(struct _chunk *, int, size_t, struct sockaddr_in *);
    void (*reset)(struct _chunk *);
    void (*clean)(struct _chunk **);
  } chunk_t;

#define CHUNK_SIZE sizeof(chunk_t)
  /* initialize struct chunk */
  chunk_t *chunk_init();

#define CHUNK_VIEW(chunk) \
  { \
    if (chunk) { \
      fprintf(stdout, "chunk:%08X\n" \
          "chunk->id:%d\n" \
          "chunk->type:%02X\n" \
          "chunk->buf:%08X\n" \
          "chunk->buf->data:%08X\n" \
          "chunk->buf->size:%u\n" \
          "chunk->file.fd:%d\n" \
          "chunk->file.name:%s\n" \
          "chunk->offset:%llu\n" \
          "chunk->len:%llu\n\n", \
          chunk, chunk->id, chunk->type, \
          chunk->buf, chunk->buf->data, chunk->buf->size, \
          chunk->file.fd, chunk->file.name, \
          chunk->offset, chunk->len); \
    } \
  }
#endif

  /* initialzie chunk */
  int chk_set(chunk_t *, int, int, char *, uint64_t, uint64_t);

  /* append data to chunk buffer */
  int chk_append_tcp(chunk_t *, void *, size_t);

  /* append data to chunk buffer */
  int chk_append_tcp_wan(chunk_t *, void *, size_t);

  int chk_append_udp(chunk_t *, void *, size_t);

  /* fill chunk with data */
  int chk_fill(chunk_t *, void *, size_t);

  /* write chunk data to udp fd */
  int chk_sendto(chunk_t *, int, size_t, struct sockaddr_in *);

  /* write chunk data to fd */
  int chk_send(chunk_t *, int, size_t);

  /* reset chunk */
  void chk_reset(chunk_t *);

  /* clean chunk */
  void chk_clean(chunk_t **);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _CHUNK_H
