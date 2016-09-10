#include "chunk.h"
#include "../core.h"

/* initialize struct chunk */
chunk_t *chunk_init()
{
  chunk_t *chunk = (chunk_t *) calloc(1, sizeof(chunk_t));
  if (chunk) {
    chunk->set = chk_set;
    chunk->append_tcp = chk_append_tcp;
    chunk->append_tcp_wan = chk_append_tcp_wan;
    chunk->append_udp = chk_append_udp;
    chunk->fill = chk_fill;
    chunk->send = chk_send;
    chunk->sendto = chk_sendto;
    chunk->reset = chk_reset;
    chunk->clean = chk_clean;
    chunk->buf = buffer_init();

    pthread_mutex_init(&(chunk->mutex), NULL);

  }
  return chunk;
}

/* initialzie chunk */
int chk_set(chunk_t *chunk, int id, int type, char *filename, uint64_t offset,
    uint64_t len)
{
  if (chunk) {
    chunk->reset(chunk);

    pthread_mutex_lock(&(chunk->mutex));

    chunk->id = id;
    chunk->type = type;
    if (chunk->buf == NULL) {
      chunk->buf = buffer_init();
    } else {
      chunk->buf->reset(chunk->buf);
    }
    chunk->file.fd = -1;
    if (filename)
      strcpy(chunk->file.name, filename);
    chunk->offset = offset;
    chunk->len = len;

    pthread_mutex_unlock(&(chunk->mutex));

  }
  return 0;
}

/* append data to chunk buffer */
int chk_append_tcp(chunk_t *chunk, void *data, size_t len)
{
  int ret = -1;
  int msg_ret = -1;

  default_head_t default_head = {
    .data_len = len
  };

  //head.data_len = strlen(data);
  //head.data_len = len;
  if (chunk) {

    pthread_mutex_lock(&(chunk->mutex));

    /*
    ret = strcmp(head.msg_info, MSG_DEFAULT_INFO);
    if (ret == 0) {
      //push head
      if (chunk->buf && chunk->buf->push(chunk->buf, &default_head, sizeof(default_head_t)) == 0) {
        chunk->len += sizeof(default_head_t);
        ret = 0;
      }
    } else {
      //push head
      if (chunk->buf && chunk->buf->push(chunk->buf, &head, sizeof(head_t)) == 0) {
        chunk->len += sizeof(head_t);
        ret = 0;
      }
    }
    */

    //push head
    if (chunk->buf && chunk->buf->push(chunk->buf, &default_head, sizeof(default_head_t)) == 0) {
      chunk->len += sizeof(default_head_t);
      ret = 0;
    }

    //push data
    if (chunk->buf && chunk->buf->push(chunk->buf, data, len) == 0) {
      chunk->len += len;
      ret = 0;
    }
    pthread_mutex_unlock(&(chunk->mutex));

  }
  return ret;
}

/* append data to chunk buffer */
int chk_append_tcp_wan(chunk_t *chunk, void *data, size_t len)
{
  int ret = -1;
  int msg_ret = -1;

  default_head_t default_head = {
    .data_len = len
  };

  wan_head_t wan_head = {
    .data_len = len,
    .send_crc32 = "aaaaaaaa6714",
    .recv_crc32 = "cccccccc6714"
  };

  //head.data_len = strlen(data);
  //head.data_len = len;
  if (chunk) {

    pthread_mutex_lock(&(chunk->mutex));

    /*
    ret = strcmp(head.msg_info, MSG_DEFAULT_INFO);
    if (ret == 0) {
      //push head
      if (chunk->buf && chunk->buf->push(chunk->buf, &default_head, sizeof(default_head_t)) == 0) {
        chunk->len += sizeof(default_head_t);
        ret = 0;
      }
    } else {
      //push head
      if (chunk->buf && chunk->buf->push(chunk->buf, &head, sizeof(head_t)) == 0) {
        chunk->len += sizeof(head_t);
        ret = 0;
      }
    }
    */

    if (len != 66) {
    //push head
    if (chunk->buf && chunk->buf->push(chunk->buf, &wan_head, sizeof(wan_head_t)) == 0) {
      chunk->len += sizeof(wan_head_t);
      ret = 0;
    }
    }

    //push data
    if (chunk->buf && chunk->buf->push(chunk->buf, data, len) == 0) {
      chunk->len += len;
      ret = 0;
    }
    pthread_mutex_unlock(&(chunk->mutex));

  }
  return ret;
}

/* append data to chunk buffer */
int chk_append_udp(chunk_t *chunk, void *data, size_t len)
{
  int ret = -1;
  int msg_ret = -1;
  default_head_t head = {
    .data_len = len
  };

  //head.data_len = strlen(data);
  //head.data_len = len;
  if (chunk) {

    pthread_mutex_lock(&(chunk->mutex));

    /*
    ret = strcmp(head.msg_info, MSG_DEFAULT_INFO);
    if (ret == 0) {

    } else {
      //push head
      if (chunk->buf && chunk->buf->push(chunk->buf, &head, sizeof(head_t)) == 0) {
        chunk->len += sizeof(head_t);
        ret = 0;
      }
    }
    */

    //push data
    if (chunk->buf && chunk->buf->push(chunk->buf, data, len) == 0) {
      chunk->len += len;
      ret = 0;
    }
    pthread_mutex_unlock(&(chunk->mutex));

  }
  return ret;
}

#ifndef CLOSE_FD
#define CLOSE_FD(_fd) \
{ \
  if(_fd > 0) { \
    close(_fd); \
  } \
  _fd = -1; \
}
#endif

/* fill chunk with data */
int chk_fill(chunk_t *chunk, void *data, size_t len)
{
  int n = 0;
  size_t size;
  if (chunk == NULL)
    return -1;
  if (chunk->len <= 0)
    return 0;

  pthread_mutex_lock(&(chunk->mutex));

  switch (chunk->type) {
    case MEM_CHUNK:
      {
        size = (chunk->len > len) ? len : chunk->len;
        if ((n = chunk->buf->push(chunk->buf, data, (size_t) size)) != 0) {
          n = -1;
        } else {
          chunk->len -= size * 1llu;
          n = (int) size;
        }
        break;
      }
    case FILE_CHUNK:
      {
        if (chunk->file.fd < 0
            || (chunk->file.fd = open(chunk->file.name, O_CREAT | O_RDWR, 0644))
            < 0) {
          n = -1;
          break;
        }
        if (lseek(chunk->file.fd, chunk->offset, SEEK_SET) == -1) {
          n = -1;
          CLOSE_FD(chunk->file.fd);
          break;
        }
        if ((n = write(chunk->file.fd, data, len)) > 0) {
          chunk->offset += n * 1llu;
          chunk->len -= n * 1llu;
        }
        CLOSE_FD(chunk->file.fd);
        break;
      }
    default:
      n = -1;
  }

  pthread_mutex_unlock(&(chunk->mutex));

  return n;
}

/* write chunk data to udp fd */
int chk_sendto(chunk_t *chunk, int fd, size_t buf_size,
    struct sockaddr_in *udp_sa)
{
  int n = 0, len = 0;
  size_t m_size;
  void *data = NULL;
  void *buf = NULL;
  int _opt = 1;

  //测试
  char address[INET_ADDRSTRLEN] = {0};
  inet_ntop(AF_INET, &(udp_sa->sin_addr), address, sizeof(address));

  setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (char *) &_opt, (socklen_t) sizeof(_opt));

  if (chunk == NULL)
    return -1;
  if (chunk->len <= 0)
    return -1;

  /*
  char head_buf[HEAD_SIZE] = {0};
  memcpy(head_buf, (chunk->buf->data) + chunk->offset, HEAD_SIZE);
  head_t *head = (head_t *) head_buf;
  */

  pthread_mutex_lock(&(chunk->mutex));
  switch (chunk->type) {
    case MEM_CHUNK:
      {
        /*
           if( (n = sendto(fd, ((char *)(chunk->buf->data) + chunk->offset),
           chunk->len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr))) < 0 )
           */
        /*
        if ((n = sendto(fd, ((char *) (chunk->buf->data) + chunk->offset),
                (HEAD_SIZE + head->data_len), 0, (struct sockaddr *) udp_sa,
                sizeof(struct sockaddr))) < 0) {
                */
        if ((n = sendto(fd, ((char *) (chunk->buf->data) + chunk->offset),
                chunk->len, 0, (struct sockaddr *) udp_sa,
                sizeof(struct sockaddr))) < 0) {
          n = -1;
        } else {
          chunk->offset += n * 1llu;
          chunk->len -= n * 1llu;
        }
        //LOGI("@tim write udp data %s %d \n", address, n);
        break;
      }
    default:
      return n = -1;
  }
  pthread_mutex_unlock(&(chunk->mutex));

  return n;
}

/* write chunk data to fd */
int chk_send(chunk_t *chunk, int fd, size_t buf_size)
{
  int n = 0, len = 0;
  size_t m_size;
  void *data = NULL;
  void *buf = NULL;

  //测试
  socklen_t sa_len = sizeof(struct sockaddr_in);
  struct sockaddr_in tcp_sa;
  char address[INET_ADDRSTRLEN] = {0};
  getpeername(fd, (struct sockaddr *) &(tcp_sa), &sa_len);
  inet_ntop(AF_INET, &(tcp_sa.sin_addr), address, sizeof(address));
  char packet_head_buffer[HEAD_SIZE] = {0};

  if (chunk == NULL)
    return -1;
  if (chunk->len <= 0)
    return -1;

  pthread_mutex_lock(&(chunk->mutex));
  switch (chunk->type) {
    case MEM_CHUNK:
      {
        if ((n = write(fd, ((char *) (chunk->buf->data) + chunk->offset),
                chunk->len)) < 0) {
          n = -1;
        } else {
          chunk->offset += n * 1llu;
          chunk->len -= n * 1llu;
        }

        //memcpy(packet_head_buffer, chunk->buf->data, HEAD_SIZE);
        //head_t *packet_head = (head_t *) packet_head_buffer;
        //LOGI("@tim chunk send data size_ = %d \n", packet_head->data_len);

        //LOGI("@tim write tcp data %s %d \n", address, n);
        break;
      }
    case FILE_CHUNK:
      {
        if (chunk->file.fd < 0) {
          if ((chunk->file.fd = open(chunk->file.name, O_RDONLY)) < 0) {
            n = -1;
            goto end;
          }
        }
        if (lseek(chunk->file.fd, (off_t) chunk->offset, SEEK_SET) == -1) {
          n = -1;
          fprintf(stderr, "LSEEK %u failed, %s\n", chunk->offset, strerror(errno));
          goto end;
        }
#ifdef _USE_MMAP
        m_size = (chunk->len > buf_size)
          ? buf_size : (size_t)(chunk->len);
        if( (data = mmap(NULL, m_size, PROT_READ, MAP_PRIVATE,
                chunk->file.fd, 0)) == MAP_FAILED)
        {
          n = -1;
          fprintf(stderr, "MMAP %d size:%u failed, %s\n",
              chunk->file.fd, m_size, strerror(errno));
          goto end;
        }
#else // _USE_MMAP
        data = buf = (void *) calloc(1, buf_size);
        if ((len = read(chunk->file.fd, data, buf_size)) < 0) {
          n = -1;
          fprintf(stderr, "READ %d failed, %s\n", chunk->file.fd, strerror(errno));
          goto end;
        } else {
          m_size = len;
        }
#endif // _USE_MMAP
        if ((n = write(fd, data, m_size)) < 0) {
          n = -1;
          fprintf(stderr, "WRITE %d failed, %s\n", chunk->file.fd, strerror(errno));
          goto end;
        } else {
          chunk->offset += n * 1llu;
          chunk->len -= n * 1llu;
        }
#ifdef _USE_MMAP
        munmap(data, m_size);
#endif // _USE_MMAP

end:{
      if (buf)
        free(buf);
      CLOSE_FD(chunk->file.fd);
    }
    break;
      }

    default:
      return n = -1;
  }
  pthread_mutex_unlock(&(chunk->mutex));
  return n;
}

/* reset chunk */
void chk_reset(chunk_t *chunk)
{
  if (chunk) {

    pthread_mutex_lock(&(chunk->mutex));

    switch (chunk->type) {
      case MEM_CHUNK:
        {
          chunk->buf->reset(chunk->buf);
        }
      case FILE_CHUNK:
        {
          CLOSE_FD(chunk->file.fd);
          break;
        }
      default:
        break;

    }
    chunk->id = 0;
    chunk->type = 0;
    chunk->offset = 0llu;
    chunk->len = 0llu;

    pthread_mutex_unlock(&(chunk->mutex));

  }
}

/* clean chunk buffer data and close opened fd */
void chk_clean(chunk_t **chunk)
{
  if ((*chunk) == NULL)
    return;
  //chunk->reset(chunk);
  if ((*chunk)->buf) {
    (*chunk)->buf->clean(&(*chunk)->buf);
  }

  pthread_mutex_destroy(&((*chunk)->mutex));
  free((*chunk));
  (*chunk) = NULL;
  return;
}

#ifdef _DEBUG_CHUNK
int main()
{
  CHUNK *chunk = chunk_init();
  char *s = "d,f.ma.sdfmds.fm;ldsmf.ds,f.ds,f/.df";
  if (chunk) {
    chunk->set(chunk, 0, MEM_CHUNK, NULL, 0, 160);
    CHUNK_VIEW(chunk);
    chunk->fill(chunk, (void *)s, strlen(s));
    CHUNK_VIEW(chunk);
    chunk->send(chunk, 0, 32);
    chunk->clean(&chunk);
  }
}
#endif // _DEBUG_CHUNK
