#include "session.h"
#include "utils/buffer.h"
#include "utils/queue.h"

/* sendqueue settting */
//sess->push_message(sess, MESSAGE_OUTPUT);

#define SENDQUEUE_SETTING(_sess) \
{ \
  if(_sess->send_queue->total != 0) { \
    _sess->event_update(_sess, EV_READ | EV_WRITE | EV_PERSIST); \
  } else { \
    _sess->event_update(_sess, EV_READ | EV_PERSIST); \
  } \
}

#define SESSION_CHECK_RET(sess, ret) \
{ \
  if(sess == NULL) { \
    _ERROR_LOG("error:session is null"); \
    return ret; \
  } \
  if(sess->transaction_state == CLOSED_STATE) return ret; \
}

#define SESSION_CHECK(sess) \
{ \
  if(sess == NULL) { \
    _ERROR_LOG("error:session is null"); \
    return ; \
  } \
  if(sess->transaction_state == CLOSED_STATE) return; \
}

/* initialize session struct */
session_t *session_init()
{
  session_t *sess = (session_t *) calloc(1, sizeof(session_t));
  if (sess == NULL) {
    _ERROR_LOG("error:calloc new session failed, %s", strerror(errno));
    return NULL;
  }

  sess->set = sess_set;
  //sess->event_update = sess_event_update;
  sess->event_handler = sess_event_handler;
  sess->read_handler = sess_read_handler;
  sess->write_handler = sess_write_handler;
  sess->push_message = sess_push_message;
  sess->push_chunk = sess_push_chunk;
  sess->push_file = sess_push_file;
  sess->state_handler = sess_state_handler;
  sess->terminate = sess_terminate;
  sess->clean = sess_clean;
  sess->parse_packet = sess_parse_packet;
  sess->parse_packet_wan = sess_parse_packet_wan;

  sess->buffer = buffer_init();
  sess->chunk = chunk_init();
  sess->send_queue = queue_init();
  sess->timer = timer_init();

  sess->event = ev_init();

  sess->head_readed_bytes = 0;
  sess->body_readed_bytes = 0;

  sess->crc32_flag = 0;
  memset((void *) sess->send_crc32, 0, 16);
  return sess;
}

/* initialize session */
int sess_set(session_t *sess, int fd, int sock_t, struct sockaddr_in *sa)
{
  socklen_t sa_len = sizeof(struct sockaddr_in);
  SESSION_CHECK_RET(sess, -1);
  sess->fd = fd;
  sess->sock_t = sock_t;
  memset((void *) &sess->udp_sa, 0, sizeof(struct sockaddr_in));
  memcpy((void *) &sess->udp_sa, (void *) sa, sizeof(struct sockaddr_in));
  sess->transaction_id = 0;
  sess->transaction_state = 0;
  sess->log = sess->pth->log;
  sess->event_flags = (E_READ | E_PERSIST);
  sess->buf_size =
    (sess->pth->sv->buf_size) ? sess->pth->sv->buf_size : BUF_SIZE;
  /* get peer name */
  getpeername(sess->fd, (struct sockaddr *) &(sess->tcp_sa), &sa_len);
  //fcntl(sess->fd, F_SETFL, O_NONBLOCK);

  //测试
  char address[INET_ADDRSTRLEN] = {0};
  inet_ntop(AF_INET, &(sess->tcp_sa.sin_addr), address, sizeof(address));
  //LOGI("@tim session set socket address %s %d \n", address, fd);
  //printf("@tim session set socket address %s %d \n", address, fd);

  /* initialize event */
  //sess->event->set(sess->event, sess->fd, E_READ | E_PERSIST, (void *)sess, sess->event_handler);
  sess->event->set(sess->event, sess->fd, E_READ | E_PERSIST, (void *)sess->pth, sess->pth->event_handler);
  sess->pth->eventbase->add(sess->pth->eventbase, sess->event);

  //return sess->event_update(sess, EV_READ | EV_PERSIST);
  return 0;
}

/* session event handler */
void sess_event_handler(int event_fd, short event, void *arg)
{
  session_t *sess = (session_t *) arg;
  if (sess) {
    if (event_fd != sess->fd) {
      ERROR_LOG(sess->log,
          "event file descriptor [%d] do not match session fd[%d]", event_fd,
          sess->fd);
      return;
    } else {
      DEBUG_LOG(sess->log, "EV_HANDLER:%d", event);
    }
    if (event & E_READ) {
      DEBUG_LOG(sess->log, "EV_READ:%d", event);
      sess->read_handler(sess);
    }
    if (event & E_WRITE) {
      DEBUG_LOG(sess->log, "EV_WRITE:%d", event);
      sess->write_handler(sess);
    }
  }
  return;
}

#if 0
/* update event base*/
int sess_event_update(session_t *sess, short new_flags)
{
  char address[INET_ADDRSTRLEN] = {0};
  inet_ntop(AF_INET, &(sess->tcp_sa.sin_addr), address, sizeof(address));

  if (sess == NULL)
    return -1;
  if (new_flags == sess->event_flags)
    return 0;
  /* delete event */
  if (new_flags == 0) {
    sess->event_flags = 0;
    DEBUG_LOG(sess->log, "deleted event[%08x] fd[%d]", &(sess->event),
        sess->fd);
    if (sess->sock_t & TCP_T) {
      LOGI("@tim deleted event new_flag == %d ip %s \n", new_flags, address);
    }
    return event_del(&(sess->event));
    //return event_del(sess->event);
  }
  /* delete old event */
  if (sess->event_flags != 0) {
    if (event_del(&(sess->event)) == -1) {
      FATAL_LOG(sess->log, "delete event[%08x] failed, %s", &(sess->event),
          strerror(errno));
      if (sess->sock_t & TCP_T) {
        LOGI("@tim deleted event failed -1 ip %s \n", address);
      }
      return -1;
    } else {
      DEBUG_LOG(sess->log, "deleted fd[%d] old event[%08x] %d", sess->fd,
          &(sess->event), sess->event_flags);
      if (sess->sock_t & TCP_T) {
        LOGI("@tim deleted old event event_flags == %d ip %s \n", sess->event_flags, address);
      }
    }
  }

  /* set new event */
  event_set(&(sess->event), sess->fd, new_flags, sess->pth->event_handler,
      (void*) sess->pth);
  event_base_set(sess->pth->eventbase, &(sess->event));
  /*
  sess->event = event_new(sess->pth->eventbase, sess->fd, new_flags, sess->pth->event_handler,
      (void*) sess->pth);
      */

  sess->event_flags = new_flags;
  if (event_add(&(sess->event), NULL) != 0) {
    FATAL_LOG(sess->log, "adding event:%d for %d failed, %s", new_flags,
        sess->fd, strerror(errno))
      if (sess->sock_t & TCP_T) {
        LOGI("@tim adding event failed ip %s \n", address);
      }
      return -1;
  }
  DEBUG_LOG(sess->log, "added event:%d for %d", new_flags, sess->fd)
    if (sess->sock_t & TCP_T) {
      LOGI("@tim adding event event_flags == %d ip %s \n", sess->event_flags, address);
    }
    return 0;
}
#endif

/* read data from fd*/
int sess_read_handler(session_t *sess)
{
  SESSION_CHECK_RET(sess, -1);
  int len, total = 0;
  void *tmp = NULL;
  int fd = -1;
  if (sess->transaction_state == CLOSED_STATE)
    return -1;

  tmp = (void *) calloc(1, sess->buf_size);

  /* reading normal data */
  if ((len = read(sess->fd, tmp, sess->buf_size)) <= 0) {
    ERROR_LOG(sess->log, "reading from %s:%d failed, %s",
        inet_ntoa(sess->tcp_sa.sin_addr), ntohs(sess->tcp_sa.sin_port),
        strerror(errno));
    goto err_end;
  }

  /* update timer */
  sess->timer->sample(sess->timer);

  sess->recv_total += len;
  /* push data to buffer */
  sess->buffer->push(sess->buffer, tmp, len);
  /* update event */
  if (len == sess->buf_size) {
    //sess->event_update(sess, EV_READ | EV_PERSIST);
  }
  DEBUG_LOG(sess->log, "read %ld byte(s) from %s:%d via fd(%d) buffer total:%u",
      len, inet_ntoa(sess->tcp_sa.sin_addr), ntohs(sess->tcp_sa.sin_port),
      sess->fd, sess->buffer->size);
  /* handling incomming buffer with chunk */
  /*
     if(sess->transaction_state == READ_CHUNK_STATE ) {
     sess->chunk_reader(sess);
     goto end;
     }
     */

  /* Reading packet */
  //sess->packet_reader(sess);	
  //LOGI("@tim session read handler readed len %d \n", len);
  char address[INET_ADDRSTRLEN] = {0};
  int  ret = -1;
  if (sess->sock_t & UDP_T) {
    inet_ntop(AF_INET, &(sess->udp_sa.sin_addr), address, sizeof(address));
    //LOGI("@tim session push udp address type %s %d \n", address, sess->sock_t);
  } else {
    inet_ntop(AF_INET, &(sess->tcp_sa.sin_addr), address, sizeof(address));
    //LOGI("@tim session push tcp address type %s %d \n", address, sess->sock_t);
  }

  sess->parse_packet_wan(sess);

end:
  {
    if (tmp)
      free(tmp);
  }
  return 0;
err_end:
  {
    if (tmp)
      free(tmp);
    sess->pth->terminate_session(sess->pth, sess);
    //sess->push_message(sess, MESSAGE_QUIT);
  }
  return -1;
}

/* wirite data to fd */
int sess_write_handler(session_t *sess)
{
  int sent = 0;
  uint64_t len = 0llu;
  chunk_t *cp = NULL;

  SESSION_CHECK_RET(sess, -1);
  /* send chunk */
  cp = (chunk_t *) (sess->send_queue->head(sess->send_queue));
  //if (cp == NULL && cp->len <= 0llu)
  if (cp == NULL || cp->len <= 0llu)
    goto end;
  len = cp->len;
  //CHUNK_VIEW(cp);
  if (sess->sock_t & TCP_T) {
    if ((sent = cp->send(cp, sess->fd, sess->buf_size)) > 0) {
      sess->send_total += sent;
      DEBUG_LOG(sess->log, "sent %u of %llu byte(s) to %s:%d via fd[%d]", sent,
          len, inet_ntoa(sess->tcp_sa.sin_addr), ntohs(sess->tcp_sa.sin_port),
          sess->fd)
        if (cp->len <= 0llu) {
          cp = (chunk_t *) sess->send_queue->pop(sess->send_queue);
          if (cp)
            cp->clean(&cp);
        }
      /* update timer */
      sess->timer->sample(sess->timer);
    } else {
      ERROR_LOG(sess->log, "sending chunk to %s:%d failed, %s",
          inet_ntoa(sess->tcp_sa.sin_addr), ntohs(sess->tcp_sa.sin_port),
          strerror(errno));
      /* error , quit */
      sess->pth->terminate_session(sess->pth, sess);
      //sess->push_message(sess, MESSAGE_QUIT);
      return -1;
    }
  }
  if (sess->sock_t & UDP_T) {
    if ((sent = cp->sendto(cp, sess->fd, sess->buf_size, &sess->udp_sa)) > 0) {
      sess->send_total += sent;
      DEBUG_LOG(sess->log, "sent %u of %llu byte(s) to %s:%d via fd[%d]", sent,
          len, inet_ntoa(sess->tcp_sa.sin_addr), ntohs(sess->tcp_sa.sin_port),
          sess->fd)
        if (cp->len <= 0llu) {
          cp = (chunk_t *) sess->send_queue->pop(sess->send_queue);
          if (cp)
            cp->clean(&cp);
        }
      /* update timer */
      sess->timer->sample(sess->timer);
    } else {
      ERROR_LOG(sess->log, "sending chunk to %s:%d failed, %s",
          inet_ntoa(sess->tcp_sa.sin_addr), ntohs(sess->tcp_sa.sin_port),
          strerror(errno));
      /* error , quit */
      sess->pth->terminate_session(sess->pth, sess);
      //sess->push_message(sess, MESSAGE_QUIT);
      return -1;
    }
  }
end:
  {
    //SENDQUEUE_SETTING(sess);
    if (sess->send_queue->total == 0) {
      sess->event->del(sess->event, E_WRITE);
    }
  }
  return 0;
}

/* push message to pthread joblist queue */
void sess_push_message(session_t *sess, int msg_id)
{
  message_t *msg = NULL;
  SESSION_CHECK(sess);

  //pthread_mutex_lock(&(sess->pth->mutex));
  if (msg_id == MESSAGE_QUIT)
    sess->transaction_state = CLOSED_STATE;
  if ((msg = message_init()) == NULL) {
    ERROR_LOG(sess->log, "initialize message failed, %s", strerror(errno));
    //pthread_mutex_unlock(&(sess->pth->mutex));
    return;
  } else {
    DEBUG_LOG(sess->log, "initialize new message[%d] for session[%d]", msg_id,
        sess->fd);
  }
  msg->msg_id = msg_id;
  msg->fd = sess->fd;
  //msg->handler = sess;
  sess->pth->message_queue->push(sess->pth->message_queue, (void *) msg);
  //pthread_mutex_unlock(&(sess->pth->mutex));
  return;
}

/* add mem_chunk to send queue */
int sess_push_chunk(session_t *sess, void *data, size_t len)
{
  chunk_t *cp = NULL;
  int ret = -1;

  SESSION_CHECK_RET(sess, -1);
  cp = (chunk_t *) (sess->send_queue->tail(sess->send_queue));

  char address[INET_ADDRSTRLEN] = {0};
  if (sess->sock_t & UDP_T) {
    inet_ntop(AF_INET, &(sess->udp_sa.sin_addr), address, sizeof(address));
    //LOGI("@tim session push udp address type %s %d \n", address, sess->sock_t);
  } else {
    inet_ntop(AF_INET, &(sess->tcp_sa.sin_addr), address, sizeof(address));
    //LOGI("@tim session push tcp address type %s %d \n", address, sess->sock_t);
  }

  if (cp != NULL && cp->type == MEM_CHUNK) {
    if (sess->sock_t & TCP_T) {
      //LOGI("@tim cp != NULL session push chunk data %s \n", data);
    }

    if (sess->sock_t & TCP_T) {

      cp->append_tcp_wan(cp, data, len);
    } else {

      cp->append_udp(cp, data, len);
    }
  } else {
    cp = chunk_init();
    cp->set(cp, sess->transaction_id, MEM_CHUNK, NULL, 0llu, 0llu);
    if (sess->sock_t & TCP_T) {
      //LOGI("@tim cp == NULL session push chunk data %s type %d \n", data, cp->type);
    }
    if (sess->sock_t & TCP_T) {

        cp->append_tcp_wan(cp, data, len);
    } else {

      cp->append_udp(cp, data, len);
    }
    sess->send_queue->push(sess->send_queue, (void *) cp);
    //CHUNK_VIEW(cp);
    //QUEUE_VIEW(sess->send_queue);
  }
  //SENDQUEUE_SETTING(sess);
  sess->event->add(sess->event, E_WRITE);
  //QUEUE_VIEW(sess->send_queue);
  return 0;
}

/* add file_chunk to send queue */
int sess_push_file(session_t *sess, char *filename, uint64_t offset,
    uint64_t len)
{
  chunk_t *cp = NULL;

  SESSION_CHECK_RET(sess, -1);
  cp = chunk_init();
  cp->set(cp, sess->transaction_id, FILE_CHUNK, filename, offset, len);
  sess->send_queue->push(sess->send_queue, (void *) cp);
  //SENDQUEUE_SETTING(sess);
  sess->event->add(sess->event, E_WRITE);
  return 0;
}

/* set session transaction state */
int sess_set_transaction_state(session_t *sess, uint32_t state)
{
  if (sess && (state & TRANSACTION_STATES)) {
    sess->transaction_state = state;
    return 0;
  }
  return -1;
}

/* set session transaction state */
int sess_set_transaction_id(session_t *sess, uint32_t transaction_id)
{
  if (sess && transaction_id > 0) {
    sess->transaction_id = transaction_id;
    return 0;
  }
  return -1;
}

/* check connection state send oob data ensure connection is connected */
int sess_state_handler(session_t *sess)
{
  if (sess) {
    /*
       if(send(sess->fd, (void *)"0", 1, MSG_OOB) < 0 ) {
       ERROR_LOG(sess->log, "sending oob data failed, %s", strerror(errno));	
       goto terminate_session;
       }
       */
    if ((time(NULL) - sess->timer->last_sec) >= sess->pth->sv->conn_timeout) {
      ERROR_LOG(sess->log, "connection timeout %d seconds",
          sess->pth->sv->conn_timeout);
      //printf("connection timeout %d seconds \n", sess->pth->sv->conn_timeout);
      goto terminate_session;
    }
    return 0;
terminate_session:
    {
      sess->push_message(sess, MESSAGE_QUIT);
      return -1;
    }
  }
}

int sess_parse_packet(session_t *sess)
{
  buffer_t *buffer_;
  buffer_ = sess->buffer;
  char data_buffer_[1024 * 8] = {0};
  char address[INET_ADDRSTRLEN] = {0};
  uint16_t head_readed_bytes = 0;
  uint32_t body_readed_bytes = 0;
  char *packet_head_buffer = NULL;
  uint32_t head_remain_bytes = 0;

  message_t *msg = NULL;
  server_t *sv = sess->pth->sv;

  //printf("sess->buffer %s \n", buffer_ + 64);
  while (buffer_->size) {

    head_readed_bytes = sess->head_readed_bytes;
    body_readed_bytes = sess->body_readed_bytes;
    packet_head_buffer = sess->packet_head_buffer;
    head_remain_bytes = HEAD_SIZE - head_readed_bytes;
    memset(sess->packet_head_buffer, 0, HEAD_SIZE);

    if (head_remain_bytes > 0) {
      uint32_t head_copy_bytes =
        head_remain_bytes > buffer_->size ? buffer_->size : head_remain_bytes;
      memcpy(packet_head_buffer + head_readed_bytes, buffer_->data,
          head_copy_bytes);

      head_readed_bytes += head_copy_bytes;
    }

    uint32_t data_len = 0;
    uint32_t body_remain_bytes = 0;

    struct sockaddr_in tcp_sa;
    memset((void *) &tcp_sa, 0, sizeof(struct sockaddr_in));
    server_t *sv = sess->pth->sv;

    if (HEAD_SIZE == head_readed_bytes) {

      default_head_t *default_packet_head = (default_head_t *) packet_head_buffer;
      data_len = default_packet_head->data_len;
      if (!data_len) {
        //callback_function();
        sess->head_readed_bytes = 0;
        sess->body_readed_bytes = 0;
        continue;
      }
      if (buffer_->size) {
        body_remain_bytes = data_len - body_readed_bytes;
        if (buffer_->size >= (data_len + HEAD_SIZE)) {

          //callback_function();
          //buffer_->del(buffer_, HEAD_SIZE);
          memset((void *) data_buffer_, 0, sizeof(data_buffer_));
          memcpy(data_buffer_, buffer_->data, data_len + HEAD_SIZE);

          inet_ntop(AF_INET, &(sess->tcp_sa.sin_addr), address, sizeof(address));
          printf("@tim %s nbase_tcp_message_push address %s %s \n", MSG_INFO, address, data_buffer_ + HEAD_SIZE);

          //nbase_tcp_message_push(address, sizeof(address), data_buffer_, data_len);

          printf("tcp_num: %d\n", ++(sess->pth->sv->tcp_num));

          buffer_->del(buffer_, data_len + HEAD_SIZE);
          sess->head_readed_bytes = 0;
          sess->body_readed_bytes = 0;
          continue;
        } else {
          //LOGI("@tim %s buffer_->size < data_len %d %d \n", MSG_DEFAULT_INFO, buffer_->size, data_len);
          memset(sess->packet_head_buffer, 0, HEAD_SIZE);
          return 0;
        }
      }
    }
  }
}

int sess_parse_packet_wan(session_t *sess)
{
  buffer_t *buffer_;
  buffer_ = sess->buffer;
  char data_buffer_[1024 * 8] = {0};
  char address[INET_ADDRSTRLEN] = {0};
  uint16_t head_readed_bytes = 0;
  uint32_t body_readed_bytes = 0;
  char *packet_head_buffer = NULL;
  uint32_t head_remain_bytes = 0;
  
  char recv_data[128] = {0};
  char status_code[16] = "OK";
  wan_head_t wan_head;

  message_t *msg = NULL;
  server_t *sv = sess->pth->sv;

  while (buffer_->size) {

    head_readed_bytes = sess->head_readed_bytes;
    body_readed_bytes = sess->body_readed_bytes;
    packet_head_buffer = sess->packet_wan_head_buffer;
    head_remain_bytes = WAN_HEAD_SIZE - head_readed_bytes;
    memset(sess->packet_wan_head_buffer, 0, WAN_HEAD_SIZE);

    if (head_remain_bytes > 0) {
      uint32_t head_copy_bytes =
        head_remain_bytes > buffer_->size ? buffer_->size : head_remain_bytes;
      memcpy(packet_head_buffer + head_readed_bytes, buffer_->data,
          head_copy_bytes);

      head_readed_bytes += head_copy_bytes;
    }

    uint32_t data_len = 0;
    uint8_t *send_crc32 = NULL;
    uint8_t *recv_crc32 = NULL;
    uint32_t body_remain_bytes = 0;

    int ret = 0;

    node_t *node = NULL;

    struct sockaddr_in tcp_sa;
    memset((void *) &tcp_sa, 0, sizeof(struct sockaddr_in));
    server_t *sv = sess->pth->sv;

    if (WAN_HEAD_SIZE == head_readed_bytes) {

      wan_head_t *wan_packet_head = (wan_head_t *) packet_head_buffer;
      data_len = wan_packet_head->data_len;
      send_crc32 = wan_packet_head->send_crc32;
      recv_crc32 = wan_packet_head->recv_crc32;
      if (!data_len) {
        //callback_function();
        sess->head_readed_bytes = 0;
        sess->body_readed_bytes = 0;
        continue;
      }
      if (buffer_->size) {
        body_remain_bytes = data_len - body_readed_bytes;
        if (buffer_->size >= (data_len + WAN_HEAD_SIZE)) {

          //callback_function();
          //buffer_->del(buffer_, HEAD_SIZE);
          memset((void *) data_buffer_, 0, sizeof(data_buffer_));
          memcpy(data_buffer_, buffer_->data, data_len + WAN_HEAD_SIZE);

          inet_ntop(AF_INET, &(sess->tcp_sa.sin_addr), address, sizeof(address));
          printf("data_len %d send_crc32 %s recv_crc32 %s socket %d \n", data_len, send_crc32, recv_crc32, sess->fd);
          printf("@tim %s nbase_tcp_message_push address %s %s \n", MSG_INFO, address, data_buffer_ + WAN_HEAD_SIZE);

          /*
          if (data_len != 2) {

            memset((void *) recv_data, 0, sizeof(recv_data));
            memset((void *) &wan_head, 0, sizeof(wan_head_t));
            wan_head.data_len = 2;
            strcpy(wan_head.send_crc32, recv_crc32);
            strcpy(wan_head.recv_crc32, send_crc32);
            memcpy((char *) recv_data, (void *) &wan_head, sizeof(wan_head_t));
            memcpy((char *) recv_data + 64, status_code, strlen(status_code));
            sess->push_chunk(sess, recv_data, 64 + strlen(status_code));
          }
          
          if ((ret = strcmp(recv_crc32, "000000000000")) != 0) {
            sess->pth->sv->send_flag = 1;
          }
          */

          if (sess->crc32_flag == 0) {

            printf("sess->crc32_flag == 0 \n");
            pthread_mutex_lock(&sv->mutex);

            memcpy(sess->send_crc32, data_buffer_ + 4, 16);
            if ((node = sv->socktree->search(sv->socktree, sv->socktree->root, sess->send_crc32)) != NULL) {
 
              sv->socktree->delete_node(sv->socktree, &sv->socktree->root, sess->send_crc32);
            }
            sv->socktree->create(sv->socktree, &(sv->socktree->root), sess->fd,
                sess->send_crc32);
            sess->crc32_flag = 1;

            pthread_mutex_unlock(&sv->mutex);
          }

          //printf("@tim recv_crc32 %s \n", recv_crc32);
          if ((ret = strcmp(recv_crc32, "000000000000")) == 0) {
            msg = message_init();
            if (msg) {
              msg->msg_id = MESSAGE_ECHO_ALL;
              msg->fd = sess->fd;

              memset((void *) msg->send_crc32, 0, sizeof(msg->send_crc32));
              memcpy(msg->send_crc32, data_buffer_ + 4, 16);

              memset((void *) msg->data, 0, sizeof(msg->data));
              memcpy(msg->data, data_buffer_, data_len + 64);
              msg->data_size = data_len;
              sv->message_queue->push(sv->message_queue, (void *) msg);
              msg = NULL;
            }

          } else {
            msg = message_init();
            if (msg) {
              msg->msg_id = MESSAGE_ECHO_TCP;
              msg->fd = sess->fd;

              memset((void *) msg->send_crc32, 0, sizeof(msg->send_crc32));
              memcpy(msg->send_crc32, data_buffer_ + 4, 16);

              memset((void *) msg->recv_crc32, 0, sizeof(msg->recv_crc32));
              memcpy(msg->recv_crc32, data_buffer_ + 20, 16);

              memset((void *) msg->data, 0, sizeof(msg->data));
              memcpy(msg->data, data_buffer_, data_len + 64);
              msg->data_size = data_len;
              sv->message_queue->push(sv->message_queue, (void *) msg);
              msg = NULL;
            }
          }

          //nbase_tcp_message_push(address, sizeof(address), data_buffer_, data_len);

          //printf("recv tcp socket buf: %s\n", data_buffer_);
          printf("tcp_num: %d \n", ++(sess->pth->sv->tcp_num));

          buffer_->del(buffer_, data_len + WAN_HEAD_SIZE);
          sess->head_readed_bytes = 0;
          sess->body_readed_bytes = 0;
          continue;
        } else {
          //LOGI("@tim %s buffer_->size < data_len %d %d \n", MSG_DEFAULT_INFO, buffer_->size, data_len);
          memset(sess->packet_wan_head_buffer, 0, WAN_HEAD_SIZE);
          sess->head_readed_bytes = 0;
          sess->body_readed_bytes = 0;
          return 0;
        }
      }

    } else {
      memset(sess->packet_wan_head_buffer, 0, WAN_HEAD_SIZE);
      sess->head_readed_bytes = 0;
      sess->body_readed_bytes = 0;
      return 0;
    }
  }
}

/* terminate session */
int sess_terminate(session_t *sess)
{

  if (sess) {
    sess->transaction_state = CLOSED_STATE;
    DEBUG_LOG(sess->log, "terminating connection[%d] %s:%d", sess->fd,
        inet_ntoa(sess->tcp_sa.sin_addr), ntohs(sess->tcp_sa.sin_port));
    //sess->event_update(sess, 0);
    sess->event->destroy(sess->event);
    DEBUG_LOG(sess->log, "closing ev");
    shutdown(sess->fd, SHUT_RDWR);
    close(sess->fd);
    sess->pth->sv->running_connections--;
  }
  return 0;
}

/* clean session */
void sess_clean(session_t **sess)
{
  chunk_t *chunk = NULL;
  buffer_t *buf = NULL;
  if ((*sess)) {
    DEBUG_LOG((*sess)->log, "cleaning connection[%d] %s:%d", (*sess)->fd,
        inet_ntoa((*sess)->tcp_sa.sin_addr), ntohs((*sess)->tcp_sa.sin_port));
    /* clean send queue */
    if ((*sess)->send_queue) {
      while ((*sess)->send_queue->total > 0) {
        chunk = (chunk_t *) (*sess)->send_queue->pop((*sess)->send_queue);
        if (chunk)
          chunk->clean(&chunk);
      }
      (*sess)->send_queue->clean(&((*sess)->send_queue));
    }
    /* clean buffer	 */
    if ((*sess)->buffer) {
      (*sess)->buffer->clean(&((*sess)->buffer));
    }
    /* clean chunk  */
    if ((*sess)->chunk)
      (*sess)->chunk->clean(&((*sess)->chunk));

    /* clean (*sess) */
    free((*sess));
    (*sess) = NULL;
  }
  return;
}
