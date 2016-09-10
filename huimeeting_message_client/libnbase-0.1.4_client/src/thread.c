#include "thread.h"
#include "session.h"
#include "utils/buffer.h"
#include "utils/queue.h"
#include "utils/timer.h"

#define THREAD_CHECK_RET(pth, ret) \
{ \
  if(pth == NULL) { \
    _ERROR_LOG("fatal:thread is null"); \
    return ret; \
  } \
}

#define THREAD_CHECK(pth) \
{ \
  if(pth == NULL) { \
    _ERROR_LOG("fatal:thread is null"); \
    return; \
  } \
}

/* initialize thread struct */
thread_t *thread_init()
{
  thread_t *pth = (thread_t *) calloc(1, sizeof(thread_t));
  if (pth == NULL) {
    _ERROR_LOG("error:calloc new thread failed, %s", strerror(errno));
    return NULL;
  }

  pth->event_handler = pth_event_handler;
  pth->run = pth_run;
  pth->addconn = pth_addconn;
  pth->add_session = pth_add_session;
  pth->push_data = pth_push_data;
  pth->terminate_session = pth_terminate_session;
  pth->state_conns = pth_state_conns;
  pth->terminate = pth_terminate;
  pth->clean = pth_clean;

  pth->running_status = 1;
  pth->message_queue = queue_init();
  //pth->eventbase = (struct event_base *) event_init();
  pth->eventbase = evbase_init();
  pth->timer = timer_init();
  pthread_mutex_init(&pth->mutex, NULL);
  return pth;
}

/* thread event handler */
void pth_event_handler(int event_fd, short event, void *arg)
{
  session_t *sess = NULL;
  short flags = event;
  thread_t *pth = (thread_t *) arg;

  //测试
  socklen_t sa_len = sizeof(struct sockaddr_in);
  struct sockaddr_in tcp_sa;
  char address[INET_ADDRSTRLEN] = {0};
  getpeername(event_fd, (struct sockaddr *) &(tcp_sa), &sa_len);
  inet_ntop(AF_INET, &(tcp_sa.sin_addr), address, sizeof(address));
  //LOGI("@tim thread event handler socket address %s %d \n", address, event_fd);
  //printf("@tim thread event handler socket address %s %d \n", address, event_fd);

  if (pth && pth->sessions && (sess = pth->sessions[event_fd])) {

    if (event_fd != sess->fd) {
      ERROR_LOG(pth->log,
          "event file descriptor [%d] do not match session fd[%d]", event_fd,
          sess->fd);
      return;
    } else {
      DEBUG_LOG(sess->log, "EV_HANDLER:%d", event);
    }
    if (flags & E_READ) {
      DEBUG_LOG(pth->log, "EV_READ:%d", event);
      if (sess->read_handler(sess) != 0)
        return;
      flags ^= E_READ;
    }
    if (flags & E_WRITE) {
      DEBUG_LOG(pth->log, "EV_WRITE:%d", event);
      if (sess->write_handler(sess) != 0)
        return;
      flags ^= E_WRITE;
    }
    if (flags != 0) {
      ERROR_LOG(pth->log, "UNKOWN EV:%d", flags);
      pth->terminate_session(pth, sess);
    }
  }
  return;
}

/* running thread */
void *pth_run(void *arg)
{
  message_t *msg = NULL;
  thread_t *pth = (thread_t *) arg;
  //session_t *sess = NULL;
  session_t *session = NULL;
  uint64_t n = 0;

  THREAD_CHECK_RET(pth, NULL);
  /* running */
  pth->thread_id = pthread_self();
  while (pth->running_status) {
    /* check connection state */
    if (pth->timer) {
      if ((time(NULL) - pth->timer->last_sec) >= pth->sv->conn_timeout) {
        DEBUG_LOG(pth->log, "thread[%08x] heartbeat %d", pth->thread_id, ++n);
        //pthread_mutex_lock(&(pth->sv->mutex));
        pth->state_conns(pth);
        pth->timer->sample(pth->timer);
        //pthread_mutex_unlock(&(pth->sv->mutex));
      }
    }
    /* event loop */
    //event_base_loop(pth->eventbase, EVLOOP_ONCE | EVLOOP_NONBLOCK);
    pth->eventbase->loop(pth->eventbase, 0, NULL);
    usleep(pth->sv->sleep_usec);

    /* message queue */
    //pthread_mutex_lock(&pth->mutex);
    msg = (message_t *) (pth->message_queue->pop(pth->message_queue));
    //do {
      if (msg) {
        DEBUG_LOG(pth->log, "handling message[%08x] id[%d]", msg, msg->msg_id);
        //sess = (session_t *) msg->handler;
        //if (sess && msg->handler != pth->sessions[msg->fd])
        //goto next;
        switch (msg->msg_id) {
          /* new connection */
          case MESSAGE_NEW_SESSION:
            pth->add_session(pth, msg->fd, msg->sock_t, &msg->sa);
            break;
            /* close connection */
          case MESSAGE_QUIT:
            //if (pth->sessions[msg->fd])
            //pth->terminate_session(pth, sess);
            if (pth && pth->sessions && (session = pth->sessions[msg->fd])) {
              pth->terminate_session(pth, session);
            }
            break;
          case MESSAGE_PUSH_DATA:
            if (pth && pth->sessions && (session = pth->sessions[msg->fd])) {
              session->push_chunk(session, msg->data, msg->data_size);
            }
            break;
          case MESSAGE_INPUT:
            break;
          case MESSAGE_OUTPUT:
            if (session)
              session->write_handler(session);
            break;
          default:
            break;
        }
        //next: msg->clean(&msg);
        msg->clean(&msg);
      }
      //pthread_mutex_unlock(&pth->mutex);
    //} while (msg = (message_t *) (pth->message_queue->pop(pth->message_queue)));
  }

}

/* add new connection to thread */
int pth_addconn(thread_t *pth, int fd, int sock_t, struct sockaddr_in *sa)
{
  message_t *msg = NULL;

  THREAD_CHECK_RET(pth, -1);
  //pthread_mutex_lock(&pth->mutex);
  msg = message_init();
  if (msg) {
    DEBUG_LOG(pth->log, "initialize message[MESSAGE_NEW_SESSION]");
    msg->msg_id = MESSAGE_NEW_SESSION;
    msg->fd = fd;
    msg->sock_t = sock_t;
    memset((void *) &msg->sa, 0, sizeof(struct sockaddr_in));
    memcpy((void *) &msg->sa, (void *) sa, sizeof(struct sockaddr_in));
    pth->message_queue->push(pth->message_queue, (void *) msg);
    goto end;
  }
  //pthread_mutex_unlock(&pth->mutex);
  return -1;
end:
    //pthread_mutex_unlock(&pth->mutex);
  return 0;
}

int pth_push_data(thread_t *pth, int sockfd, char *data, int size_)
{
#if 0
  session_t *sess = NULL;
  THREAD_CHECK_RET(pth, -1);

  //pthread_mutex_lock(&pth->mutex);
  if (pth && pth->sessions && (sess = pth->sessions[sockfd])) {
    //sess->push_chunk(sess, data, strlen(data));
    sess->push_chunk(sess, data, size_);
  } else {
    LOGI("@tim thread push data failed \n");
  }
  //pthread_mutex_unlock(&pth->mutex);

  return 0;
#endif

  message_t *msg = NULL;
  //pthread_mutex_lock(&pth->mutex);
  msg = message_init();
  if (msg) {
    msg->msg_id = MESSAGE_PUSH_DATA;
    msg->fd = sockfd;
    memset((void *) msg->data, 0, sizeof(msg->data));
    memcpy(msg->data, data, size_);
    msg->data_size = size_;
    pth->message_queue->push(pth->message_queue, (void *) msg);
    goto end;
  }
  //pthread_mutex_unlock(&pth->mutex);
  return -1;
end:
    //pthread_mutex_unlock(&pth->mutex);
  return 0;
}

/* check connection stats */
void pth_state_conns(thread_t *pth)
{
  session_t *sess = NULL;
  int i = 0;

  THREAD_CHECK(pth);
  /* stop and free sessions */
  if (pth->sessions) {
    DEBUG_LOG(pth->log, "checking connections state");
    for (i = 0; i < pth->sv->max_connections; i++) {
      if ((sess = pth->sessions[i]) != NULL)
        sess->state_handler(sess);
    }
  }
}

/* add new session to thread */
int pth_add_session(thread_t *pth, int fd, int sock_t,
    struct sockaddr_in *sa)
{
  session_t *sess = NULL;

  THREAD_CHECK_RET(pth, -1);
  /* check sessions and initialize */
  if (pth->sessions == NULL) {
    pth->sessions = (session_t **) calloc(pth->sv->max_connections,
        sizeof(session_t *));
  }
  /* initialize new session */
  if (pth->sessions) {
    if (pth->sessions[fd]) {
      DEBUG_LOG(pth->log, "session[%d] is exists", fd);
      pth->terminate_session(pth, pth->sessions[fd]);
    }
    DEBUG_LOG(pth->log, "adding new session[%d]", fd);
    if ((sess = session_init()) != NULL) {
      pth->sessions[fd] = sess;
      /* base setting */
      sess->pth = pth;
      if (sess->set(sess, fd, sock_t, sa) != 0) {
        FATAL_LOG(pth->log, "initialize new session[%d] failed");
        pth->terminate_session(pth, sess);
        return -1;
      }
    } else {
      ERROR_LOG(pth->log, "initialize new session failed, %s", strerror(errno));
      return -1;
    }
  } else {
    ERROR_LOG(pth->log, "initialize sessions failed, %s", strerror(errno));
  }
  DEBUG_LOG(pth->log, "added new session[%d]", fd);
  return 0;
}

/* terminate session */
void pth_terminate_session(thread_t *pth, session_t *sess)
{
  THREAD_CHECK(pth);

  server_t *sv_ = pth->sv;
  btree_t *tr_ = pth->sv->socktree;
  uint32_t port_ = 0;
  uint8_t host_[16] = {0};

  pthread_mutex_lock(&sv_->mutex);

  if(sess->sock_t & TCP_T) {
    inet_ntop(AF_INET, &(sess->tcp_sa.sin_addr), host_, sizeof(host_));
    port_ = ntohs(sess->tcp_sa.sin_port);
  }

  if(sess->sock_t & UDP_T) {
    inet_ntop(AF_INET, &(sess->udp_sa.sin_addr), host_, sizeof(host_));
    port_ = ntohs(sess->udp_sa.sin_port);
  }

  memset(sv_->dest_port, 0, sizeof(sv_->dest_port));
  memset(sv_->dest_host, 0, sizeof(sv_->dest_host));

  // port转为string型, 合并ip port
  sprintf(sv_->dest_port, "%d", port_);
  strcat(sv_->dest_host, host_);
  strcat(sv_->dest_host, ".");
  strcat(sv_->dest_host, sv_->dest_port);

  if (sess && sess->fd < pth->sv->max_connections) {
    pth->sessions[sess->fd] = NULL;
    tr_->delete_node(tr_, &tr_->root, sv_->dest_host);
    //tr_->delete_node(tr_, &tr_->root, sess->send_crc32);
    //LOGI("@tim btree delete node: %s\n", sv_->dest_host);
    //printf("@tim thread delete node: %s \n", sess->send_crc32);
    printf("@tim thread delete node: %s \n", sv_->dest_host);
    sess->terminate(sess);
    sess->clean(&sess);
  }
  pthread_mutex_unlock(&sv_->mutex);
}

/* terminate  threads */
void pth_terminate(thread_t *pth)
{
  int i = 0;

  THREAD_CHECK(pth);
  pth->running_status = 0;
  /* terminate sessions */
  for (i = 0; i < pth->sv->max_connections; i++) {
    //if(pth->sessions[i] != NULL)
    if (pth->sessions != NULL && pth->sessions[i] != NULL)
      pth->sessions[i]->terminate(pth->sessions[i]);
  }
}

/* clean thread child struct */
void pth_clean(thread_t **pth)
{
  message_t *msg;
  int i = 0;

  THREAD_CHECK((*pth));
  /* clean sessions */
  if ((*pth)->sessions) {
    for (i = 0; i < (*pth)->sv->max_connections; i++) {
      //if((*pth)->sessions[i] != NULL)
      if ((*pth)->sessions != NULL && (*pth)->sessions[i] != NULL)
        (*pth)->sessions[i]->clean(&((*pth)->sessions[i]));
    }
    free((*pth)->sessions);
  }
  /* clean message_queue */
  if ((*pth)->message_queue) {
    while ((*pth)->message_queue->total > 0) {
      msg = (message_t *) (*pth)->message_queue->pop((*pth)->message_queue);
      if (msg)
        msg->clean(&msg);
    }
    (*pth)->message_queue->clean(&((*pth)->message_queue));
  }
  /* clean event base */
  //if((*pth)->eventbase) event_base_free((*pth)->eventbase);
  if((*pth)->eventbase) (*pth)->eventbase->clean(&((*pth)->eventbase));

  /* clean timer */
  if ((*pth)->timer)
    (*pth)->timer->clean(&((*pth)->timer));
  return;
}
