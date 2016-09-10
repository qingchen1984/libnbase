#include "server.h"
#include "core.h"
#include "thread.h"
#include "btree.h"
#include "utils/timer.h"
#include "utils/buffer.h"
#include "utils/queue.h"
#include "utils/log.h"
#include "utils/inet_base.h"

#define SERVER_CHECK_RET(sv, ret) \
{ \
  if(sv == NULL) { \
    _ERROR_LOG("fatal:server pointer is null"); \
    return ret; \
  } \
}

#define SERVER_CHECK(sv) \
{ \
  if(sv == NULL) { \
    _ERROR_LOG("fatal:server pointer is null"); \
    return; \
  } \
}

/* initialize server struct */
server_t *server_init()
{
  server_t *sv = (server_t *) calloc(1, sizeof(server_t));
  if (sv == NULL) {
    _ERROR_LOG("fatal:calloc new server failed, %s", strerror(errno));
    return NULL;
  }
  sv->init = sv_init;
  sv->listen_sock_tcp = sv_listen_sock_tcp;
  sv->listen_sock_udp = sv_listen_sock_udp;
  sv->listen_sock_broadcast = sv_listen_sock_broadcast;
  sv->run = sv_run;
  sv->init_socket = sv_init_socket;
  sv->push_data = sv_push_data;
  sv->terminate_node = sv_terminate_node;
  sv->message_echo_all = sv_message_echo_all;
  sv->message_echo_tcp = sv_message_echo_tcp;
  sv->start = sv_start;
  sv->stop = sv_stop;
  sv->event_handler = sv_event_handler;
  sv->addconn = sv_addconn;
  sv->terminate = sv_terminate;
  sv->clean = sv_clean;

  sv->timer = timer_init();
  sv->socktree = tr_init();

  sv->tcp_set.event = ev_init();
  sv->udp_set.event = ev_init();
  sv->broadcast_set.event = ev_init();

  pthread_mutex_init(&sv->mutex, NULL);

  sv->tcp_num = 0;
  sv->udp_num = 0;
  sv->broadcast_num = 0;
  return sv;
}

/* handle event call */
void sv_event_handler(int event_fd, short event, void *arg)
{
  struct sockaddr_in tcp_sa, udp_sa, broadcast_sa;
  int fd = 0;
  int ret = -1;
  uint32_t port_ = 0;
  uint8_t host_[64] = {0};

  server_t *sv = (server_t *) arg;
  socklen_t sa_len = sizeof(struct sockaddr_in);

  SERVER_CHECK(sv);
  if (sv->tcp_set.sockfd == event_fd && sv->tcp_set.sock_t & TCP_T) {
    if ((fd = accept(event_fd, (struct sockaddr *) &tcp_sa, &sa_len)) == -1) {
      ERROR_LOG(sv->log, "accept new connetion failed, %s", strerror(errno));
      return;
    }
    DEBUG_LOG(sv->log, "accept new tcp connection(%ld)", fd);

    pthread_mutex_lock(&sv->mutex);

    getpeername(fd, (struct sockaddr *) &(tcp_sa), &sa_len);
    inet_ntop(AF_INET, &(tcp_sa.sin_addr), host_, sizeof(host_));
    port_ = ntohs(tcp_sa.sin_port);
    memset(sv->dest_port, 0, sizeof(sv->dest_port));
    memset(sv->dest_host, 0, sizeof(sv->dest_host));

    // port转为string型, 合并ip port
    sprintf(sv->dest_port, "%d", port_);
    strcat(sv->dest_host, host_);
    strcat(sv->dest_host, ".");
    strcat(sv->dest_host, sv->dest_port);

    sv->addconn(sv, fd, sv->tcp_set.sock_t, &tcp_sa);
    sv->socktree->create(sv->socktree, &(sv->socktree->root), fd,
        sv->dest_host);

    pthread_mutex_unlock(&sv->mutex);
    return;
  }

  char buf[DGRAM_SIZE] = {0};
  char packet_head_buffer[HEAD_SIZE] = {0};
  char data_buffer_[1024 * 8] = {0};

  uint32_t data_len = 0;
  uint8_t *msg_info = NULL;
  char address[INET_ADDRSTRLEN] = {0};

  if (sv->udp_set.sockfd == event_fd && sv->udp_set.sock_t & UDP_T) {

    if (recvfrom(event_fd, buf, DGRAM_SIZE, 0, (struct sockaddr *) &udp_sa,
          &sa_len) < 0) {
      ERROR_LOG(sv->log, "recvfrom udp socket failed, %s", strerror(errno));
      return;
    }

    /*
    if (HEAD_SIZE == sizeof(default_head_t)) {

      ret = strcmp(MSG_INFO_DEFAULT, MSG_INFO_NEW);
      if (ret == 0) {

        inet_ntop(AF_INET, &(udp_sa.sin_addr), address, sizeof(address));
        printf("@tim %s nbase_udp_message_push address %s %s \n", MSG_DEFAULT_INFO, address, buf);
        //nbase_udp_message_push(address, sizeof(address), buf, strlen(buf));
        ret = -1;
      } else {

        return;
      }
    } else {

      memcpy(packet_head_buffer, buf, HEAD_SIZE);
      head_t *packet_head = (head_t *) packet_head_buffer;
      msg_info = packet_head->msg_info;

      ret = strcmp(msg_info, MSG_INFO);
      if (ret == 0) {

        data_len = packet_head->data_len;
        memcpy(data_buffer_, buf + HEAD_SIZE, data_len);
        inet_ntop(AF_INET, &(udp_sa.sin_addr), address, sizeof(address));
        printf("@tim %s nbase_udp_message_push address %s %s \n", msg_info, address, data_buffer_);
        //nbase_udp_message_push(address, sizeof(address), data_buffer_, data_len);
        ret = -1;
      } else {

        return;
      }
    }
    */

    inet_ntop(AF_INET, &(udp_sa.sin_addr), address, sizeof(address));
    printf("@tim %s nbase_udp_message_push address %s %s \n", MSG_INFO, address, buf);
    //nbase_udp_message_push(address, sizeof(address), buf, strlen(buf));

    //printf("recvfrom udp socket buf: %s\n", buf + 4);
    //printf("udp_num: %d\n", ++(sv->udp_num));
    return;
  }

  if (sv->broadcast_set.sockfd == event_fd && sv->broadcast_set.sock_t & UDP_T) {

    if (recvfrom(event_fd, buf, DGRAM_SIZE, 0,
          (struct sockaddr *) &broadcast_sa, &sa_len) < 0) {
      ERROR_LOG(sv->log, "recvfrom broadcast udp socket failed, %s",
          strerror(errno));
      return;
    }

    /*
    if (HEAD_SIZE == sizeof(default_head_t)) {

      ret = strcmp(MSG_DEFAULT_INFO, MSG_INFO);
      if (ret == 0) {

        inet_ntop(AF_INET, &(broadcast_sa.sin_addr), address, sizeof(address));
        //LOGI("@tim %s nbase_broadcast_message_push address %s %s \n", MSG_DEFAULT_INFO, address, buf);
        printf("@tim %s nbase_udp_message_push address %s %s \n", MSG_DEFAULT_INFO, address, buf);
        //nbase_udp_message_push(address, sizeof(address), buf, strlen(buf));
        ret = -1;
      } else {

        return;
      }
    } else {

      memcpy(packet_head_buffer, buf, HEAD_SIZE);
      head_t *packet_head = (head_t *) packet_head_buffer;
      msg_info = packet_head->msg_info;

      ret = strcmp(msg_info, MSG_INFO);
      if (ret == 0) {

        data_len = packet_head->data_len;
        memcpy(data_buffer_, buf + HEAD_SIZE, data_len);
        inet_ntop(AF_INET, &(broadcast_sa.sin_addr), address, sizeof(address));
        //LOGI("@tim %s nbase_broadcast_message_push address %s %s \n", msg_info, address, data_buffer_);
        printf("@tim %s nbase_udp_message_push address %s %s \n", msg_info, address, data_buffer_);
        //nbase_udp_message_push(address, sizeof(address), data_buffer_, data_len);
        ret = -1;
      } else {

        return;
      }
    }
    */

    inet_ntop(AF_INET, &(broadcast_sa.sin_addr), address, sizeof(address));
    printf("@tim %s nbase_udp_message_push address %s %s \n", MSG_INFO, address, buf);
    //nbase_udp_message_push(address, sizeof(address), buf, strlen(buf));

    //printf("recvfrom broadcast udp socket buf: %s\n", buf + 4);
    //printf("broadcast_num: %d\n", ++(sv->broadcast_num));
    return;
  }
}

int sv_init(server_t *sv)
{
  int i = 0;
  int ret = 0;
  pthread_t thread_id;

  SERVER_CHECK_RET(sv, -1);

  sv->message_queue = queue_init();

  //sv->eventbase = (struct event_base *) event_init();
  sv->eventbase = evbase_init();
  sv->threads = (thread_t **) calloc(sv->max_threads, sizeof(thread_t *));
  if (sv->threads == NULL) {
    ERROR_LOG(sv->log, "initialize thread pool failed");
    return -1;
  }
  /* initialize threads pool */
  for (i = 0; i < sv->max_threads; i++) {
    sv->threads[i] = thread_init();
    if (sv->threads[i]) {
      /* base setting */
      sv->threads[i]->sv = sv;
      sv->threads[i]->index = i;
      sv->threads[i]->log = sv->log;
      /* create pthread and run */
      if (pthread_create(&thread_id, NULL, &pth_run, (void *) (sv->threads[i]))
          != 0) {
        sv->threads[i]->clean(&(sv->threads[i]));
        ERROR_LOG(sv->log, "create thread[%d] failed ", i);
        continue;
      } else {
  /*
        DEBUG_LOG(sv->log, "created thread[0x%08X] %d of %d", (int) thread_id,
            i, sv->max_threads);
            */
      }
    } else {
      ERROR_LOG(sv->log, "initialize thread failed, %s", strerror(errno));
    }
  }
  return 0;
}

int sv_listen_sock_tcp(server_t *sv)
{
  int ret = 0;

  SA_SET(sv->tcp_set.sa, sv->tcp_set.domain, sv->tcp_set.sock_t,
      sv->tcp_set.is_broadcast, sv->tcp_set.port);

  /* setting tcp */
  if (sv->tcp_set.sock_t & TCP_T) {
    sv->tcp_set.sockfd = socket(sv->tcp_set.domain, TCP_T, 0);
    if ((ret = inet_init(sv->tcp_set.sockfd, &(sv->tcp_set.sa),
            sv->tcp_set.backlog, (S_SOCK_BIND | S_SOCK_LISTEN))) != 0)
      //(S_SOCK_BIND | S_SOCK_LISTEN | S_SOCK_NONBLOCK) )) != 0 )
    {
      ERROR_LOG(sv->log, "initialize tcp server failed");
      return -1;
    }
    DEBUG_LOG(sv->log, "initialized tcpfd:%d", sv->tcp_set.sockfd);
    /*
    event_set(&sv->tcp_set.event, sv->tcp_set.sockfd, EV_READ | EV_PERSIST,
        sv->event_handler, (void *) sv);
        */
    (sv->tcp_set.event)->set(sv->tcp_set.event, sv->tcp_set.sockfd, E_READ | E_PERSIST,
        (void *) sv, sv->event_handler);
    /*
    event_base_set(sv->eventbase, &(sv->tcp_set.event));
    event_add(&sv->tcp_set.event, NULL);
    */
    sv->eventbase->add(sv->eventbase, sv->tcp_set.event);
  }
  return 0;
}

int sv_listen_sock_udp(server_t *sv)
{
  int ret = 0;

  SA_SET(sv->udp_set.sa, sv->udp_set.domain, sv->udp_set.sock_t,
      sv->udp_set.is_broadcast, sv->udp_set.port);

  if (sv->udp_set.sock_t & UDP_T) {
    sv->udp_set.sockfd = socket(sv->udp_set.domain, UDP_T, 0);
    if ((ret = inet_init(sv->udp_set.sockfd, &(sv->udp_set.sa),
            sv->udp_set.backlog, (S_SOCK_BIND | S_SOCK_NONBLOCK))) != 0) {
      ERROR_LOG(sv->log, "initialize udp server failed");
      return -1;
    }
    DEBUG_LOG(sv->log, "initialized udpfd:%d", sv->udp_set.sockfd);
    /*
    event_set(&sv->udp_set.event, sv->udp_set.sockfd, EV_READ | EV_PERSIST,
        sv->event_handler, (void *) sv);
        */
    (sv->udp_set.event)->set(sv->udp_set.event, sv->udp_set.sockfd, E_READ | E_PERSIST,
        (void *) sv, sv->event_handler);
    /*
    event_base_set(sv->eventbase, &(sv->udp_set.event));
    event_add(&sv->udp_set.event, NULL);
    */
    sv->eventbase->add(sv->eventbase, sv->udp_set.event);
  }
  return 0;
}

int sv_listen_sock_broadcast(server_t *sv)
{
  int ret = 0;

  SA_SET(sv->broadcast_set.sa, sv->broadcast_set.domain,
      sv->broadcast_set.sock_t, sv->broadcast_set.is_broadcast,
      sv->broadcast_set.port);

  if (sv->broadcast_set.sock_t & UDP_T) {
    sv->broadcast_set.sockfd = socket(sv->broadcast_set.domain, UDP_T, 0);
    if ((ret = inet_init(sv->broadcast_set.sockfd, &(sv->broadcast_set.sa),
            sv->broadcast_set.backlog, (S_SOCK_BIND | S_SOCK_NONBLOCK))) != 0) {
      ERROR_LOG(sv->log, "initialize broadcast udp server failed");
      return -1;
    }
    DEBUG_LOG(sv->log, "initialized broadcastfd:%d", sv->broadcast_set.sockfd);
    /*
    event_set(&sv->broadcast_set.event, sv->broadcast_set.sockfd,
        EV_READ | EV_PERSIST, sv->event_handler, (void *) sv);
        */
    (sv->broadcast_set.event)->set(sv->broadcast_set.event, sv->broadcast_set.sockfd, E_READ | E_PERSIST,
        (void *) sv, sv->event_handler);
    /*
    event_base_set(sv->eventbase, &(sv->broadcast_set.event));
    event_add(&sv->broadcast_set.event, NULL);
    */
    sv->eventbase->add(sv->eventbase, sv->broadcast_set.event);
  }
  return 0;
}

/* initialize socket */
int sv_init_socket(server_t *sv_, char *host_, int port_, int sock_t,
    int is_broadcast)
{
  baseset_t tcp_set, udp_set, broadcast_set;
  struct sockaddr_in sa;

  memset(sv_->dest_port, 0, sizeof(sv_->dest_port));
  memset(sv_->dest_host, 0, sizeof(sv_->dest_host));

  if (is_broadcast == 0) {
    // port转为string型, 合并ip port
    sprintf(sv_->dest_port, "%d", port_);
    strcat(sv_->dest_host, host_);
    strcat(sv_->dest_host, ".");
    strcat(sv_->dest_host, sv_->dest_port);
  } else {
    sa.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    inet_ntop(AF_INET, &(sa.sin_addr), sv_->dest_host, sizeof(sv_->dest_host));
    sprintf(sv_->dest_port, "%d", port_);
    strcat(sv_->dest_host, ".");
    strcat(sv_->dest_host, sv_->dest_port);
  }

  if (sock_t & TCP_T) {
    tcp_set.sockfd = socket(AF_INET, SOCK_STREAM, 0);
    //tcp_set.sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcp_set.sockfd < 0)
      return -1;

    tcp_set.host = sv_->dest_host;
    tcp_set.port = port_;
    tcp_set.sock_t = sock_t;
    tcp_set.is_broadcast = is_broadcast;

    tcp_set.sa.sin_family = AF_INET;
    tcp_set.sa.sin_port = htons(port_);
    tcp_set.sa.sin_addr.s_addr = inet_addr(host_);

    if (connect(tcp_set.sockfd, (struct sockaddr *) &(tcp_set.sa),
          sizeof(tcp_set.sa)) < 0)
      return -1;

    sv_->addconn(sv_, tcp_set.sockfd, tcp_set.sock_t, &(tcp_set.sa));
    sv_->socktree->create(sv_->socktree, &(sv_->socktree->root), tcp_set.sockfd,
        tcp_set.host);

    //测试
    /*
    socklen_t sa_len = sizeof(struct sockaddr_in);
    struct sockaddr_in tmp_sa;
    char address[INET_ADDRSTRLEN] = {0};
    getpeername(tcp_set.sockfd, (struct sockaddr *) &(tmp_sa), &sa_len);
    inet_ntop(AF_INET, &(tmp_sa.sin_addr), address, sizeof(address));
    LOGI("@tim tcp init socket address %s %d \n", address, tcp_set.sockfd);
    */
  }

  if ((sock_t & UDP_T) && is_broadcast == 0) {
    udp_set.sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_set.sockfd < 0)
      return -1;

    udp_set.host = sv_->dest_host;
    udp_set.port = port_;
    udp_set.sock_t = sock_t;
    udp_set.is_broadcast = is_broadcast;

    udp_set.sa.sin_family = AF_INET;
    udp_set.sa.sin_port = htons(port_);
    udp_set.sa.sin_addr.s_addr = inet_addr(host_);

    sv_->addconn(sv_, udp_set.sockfd, udp_set.sock_t, &(udp_set.sa));
    sv_->socktree->create(sv_->socktree, &(sv_->socktree->root), udp_set.sockfd,
        udp_set.host);
  }

  if ((sock_t & UDP_T) && is_broadcast != 0) {
    broadcast_set.sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (broadcast_set.sockfd < 0)
      return -1;

    broadcast_set.host = sv_->dest_host;
    broadcast_set.port = port_;
    broadcast_set.sock_t = sock_t;
    broadcast_set.is_broadcast = is_broadcast;

    broadcast_set.sa.sin_family = AF_INET;
    broadcast_set.sa.sin_port = htons(port_);
    broadcast_set.sa.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    sv_->addconn(sv_, broadcast_set.sockfd, broadcast_set.sock_t, &(broadcast_set.sa));
    sv_->socktree->create(sv_->socktree, &(sv_->socktree->root), broadcast_set.sockfd,
        broadcast_set.host);
  }

  //usleep(sv_->sleep_usec);
  return 0;
}

int sv_push_data(server_t *sv_, char *host_, int port_, char *data, int size_, int sock_t,
    int is_broadcast)
{
  node_t *node;
  int sockfd;
  struct sockaddr_in sa;

  if (is_broadcast == 0 && port_ != 255) {
    //LOGI("@tim sv push data host_ start %s %s \n", host_, data);
    //printf("@tim sv push data host_ start %s %s \n", host_, data);
  }

  pthread_mutex_lock(&sv_->mutex);

  memset(sv_->dest_port, 0, sizeof(sv_->dest_port));
  memset(sv_->dest_host, 0, sizeof(sv_->dest_host));

  if (is_broadcast == 0) {
    // port转为string型, 合并ip port
    sprintf(sv_->dest_port, "%d", port_);
    strcat(sv_->dest_host, host_);
    strcat(sv_->dest_host, ".");
    strcat(sv_->dest_host, sv_->dest_port);
  } else {
    sa.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    inet_ntop(AF_INET, &(sa.sin_addr), sv_->dest_host, sizeof(sv_->dest_host));
    sprintf(sv_->dest_port, "%d", port_);
    strcat(sv_->dest_host, ".");
    strcat(sv_->dest_host, sv_->dest_port);
  }

  if ((node = sv_->socktree->search(sv_->socktree, sv_->socktree->root, sv_->dest_host))
      == NULL) {
    //LOGI("@tim node == NULL %s \n", sv_->dest_host);
    if (sock_t & TCP_T) {
      //LOGI("@tim node == NULL init socket %s \n", sv_->dest_host);
    }

    sv_->init_socket(sv_, host_, port_, sock_t, is_broadcast);

    if ((node = sv_->socktree->search(sv_->socktree, sv_->socktree->root, sv_->dest_host))
        == NULL) {
      if (sock_t & TCP_T) {
        //LOGI("@tim node == NULL return -1 %s \n", sv_->dest_host);
      }
      pthread_mutex_unlock(&sv_->mutex);
      return -1;
    }
    else
      sockfd = node->sockfd;
  } else {
    //LOGI("@tim node != NULL %s \n", sv_->dest_host);
    sockfd = node->sockfd;
  }
  pthread_mutex_unlock(&sv_->mutex);

  int index = 0;
  thread_t *pth;

  index = sockfd % sv_->max_threads;
  pth = (thread_t *) sv_->threads[index];

  if ((pth->push_data(pth, sockfd, data, size_)) == 0) {
    if (is_broadcast == 0 && port_ != 255) {
      //LOGI("@tim sv push data host_ end %s %s \n", host_, data);
      //LOGI("@tim sv push data host_ end %s \n", host_);
      //printf("@tim sv push data host_ end %s \n", host_);
      //printf("tcp_num: %d \n", ++(sv_->tcp_num));
    }
    usleep(sv_->sleep_usec);
    return 0;
  }

  return -1;
}

int sv_terminate_node(server_t *sv_, char *host_, int port_, int sock_t,
    int is_broadcast)
{
  node_t *node;
  int sockfd;
  struct sockaddr_in sa;

  //pthread_mutex_lock(&sv_->mutex);

  memset(sv_->dest_port, 0, sizeof(sv_->dest_port));
  memset(sv_->dest_host, 0, sizeof(sv_->dest_host));

  if (is_broadcast == 0) {

    // port转为string型, 合并ip port
    sprintf(sv_->dest_port, "%d", port_);
    strcat(sv_->dest_host, host_);
    strcat(sv_->dest_host, ".");
    strcat(sv_->dest_host, sv_->dest_port);
  } else {

    sa.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    inet_ntop(AF_INET, &(sa.sin_addr), sv_->dest_host, sizeof(sv_->dest_host));
    sprintf(sv_->dest_port, "%d", port_);
    strcat(sv_->dest_host, ".");
    strcat(sv_->dest_host, sv_->dest_port);
  }

  if ((node = sv_->socktree->search(sv_->socktree, sv_->socktree->root, sv_->dest_host))
      == NULL) {

      //pthread_mutex_unlock(&sv_->mutex);
      return -1;
  } else {
    //LOGI("@tim node != NULL %s \n", sv_->dest_host);
    sockfd = node->sockfd;
  }
  //pthread_mutex_unlock(&sv_->mutex);

  int index = 0;
  thread_t *pth = NULL;
  session_t *sess = NULL;

  index = sockfd % sv_->max_threads;
  pth = (thread_t *) sv_->threads[index];

  if (pth && pth->sessions && (sess = pth->sessions[sockfd])) {

      pth->terminate_session(pth, sess);
  }
}

/* echo message for all socket */
void sv_message_echo_all(server_t *sv_, char *data, int size_)
{

  btree_t *tree = sv_->socktree;
  node_t *root = sv_->socktree->root;
  node_t *min_node = tree->search_min(tree, root);
  node_t *max_node = tree->search_max(tree, root);
  //printf("@tim min_node max_node %d %d \n", min_node->sockfd, max_node->sockfd);
  node_t *p = NULL;
  int32_t ret;

  int sockfd;
  int index = 0;
  thread_t *pth;

  //printf("@tim max_node->key min_node->key data %s %s %s \n", max_node->key, min_node->key, data + 64);
  ret = strcmp(max_node->key, min_node->key);
  if (ret == 0) {

    sockfd = min_node->sockfd;
    index = sockfd % sv_->max_threads;
    pth = (thread_t *) sv_->threads[index];

    pth->push_data(pth, sockfd, data, size_ + 64);
    //usleep(sv_->sleep_usec);
  } else {

    sockfd = min_node->sockfd;
    index = sockfd % sv_->max_threads;
    pth = (thread_t *) sv_->threads[index];

    pth->push_data(pth, sockfd, data, size_ + 64);
    //usleep(sv_->sleep_usec);

    p = tree->search_successor(tree, min_node);

    do {
      ret = strcmp(max_node->key, p->key);

      if (ret == 0) {

        sockfd = p->sockfd;
        index = sockfd % sv_->max_threads;
        pth = (thread_t *) sv_->threads[index];

        pth->push_data(pth, sockfd, data, size_ + 64);
        //usleep(sv_->sleep_usec);
      } else {

        sockfd = p->sockfd;
        index = sockfd % sv_->max_threads;
        pth = (thread_t *) sv_->threads[index];

        pth->push_data(pth, sockfd, data, size_ + 64);
        //usleep(sv_->sleep_usec);

        p = tree->search_successor(tree, p);
      }
    } while(ret != 0);

  }
}

/* echo message for all socket */
void sv_message_echo_tcp(server_t *sv_, char *data, int size_, char *recv_crc32)
{
  node_t *node;
  int sockfd;

  pthread_mutex_lock(&sv_->mutex);

  if ((node = sv_->socktree->search(sv_->socktree, sv_->socktree->root, recv_crc32))
      == NULL) {

  } else {
    sockfd = node->sockfd;
  }
  pthread_mutex_unlock(&sv_->mutex);

  int index = 0;
  thread_t *pth;

  index = sockfd % sv_->max_threads;
  pth = (thread_t *) sv_->threads[index];

  if ((pth->push_data(pth, sockfd, data, size_ + 64)) == 0) {

    //usleep(sv_->sleep_usec);
  }
}

/* run sv */
void sv_run(server_t *sv)
{
  message_t *msg;
  uint64_t n = 0;

  SERVER_CHECK(sv);

  if (sv->heartbeat_handler && sv->timer) {
    sv->timer->callback = sv->heartbeat_handler;
  }
  while (sv->running_status) {
    //event_base_loop(sv->eventbase, EVLOOP_ONCE | EVLOOP_NONBLOCK);
    sv->eventbase->loop(sv->eventbase, 0, NULL);
    usleep(sv->sleep_usec);

    if (sv->timer) {
      sv->timer->check(sv->timer, sv->heartbeat_interval);
    }

    /* message queue */
    /*
    msg = (message_t *) (sv->message_queue->pop(sv->message_queue));
    if (msg) {

      switch (msg->msg_id) {
        case MESSAGE_ECHO_ALL:
          sv->message_echo_all(sv, msg->data, msg->data_size);
          break;
        case MESSAGE_ECHO_TCP:
          sv->message_echo_tcp(sv, msg->data, msg->data_size, msg->recv_crc32);
          break;
        default:
          break;
      }
      msg->clean(&msg);
    }
    */

  }
}

/* add new connection to threads */
int sv_addconn(server_t *sv, int sockfd, int sock_t, struct sockaddr_in *sa)
{
  int index;
  thread_t *pth;

  SERVER_CHECK_RET(sv, -1);
  //sv->running_status = 1;
  if (sv->running_connections >= sv->max_connections) {
    ERROR_LOG(sv->log, "connection is full");
    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
    return -1;
  }
  index = sockfd % sv->max_threads;
  pth = (thread_t *) sv->threads[index];
  if (pth == NULL) {
    ERROR_LOG(sv->log, "thread[%u] is null", index);
    return -1;
  }
  if ((pth->addconn(pth, sockfd, sock_t, sa)) == 0) {
    sv->running_connections++;
    DEBUG_LOG(sv->log, "added new session[%ld] total %ld ", sockfd,
        sv->running_connections);
    return 0;
  }
  return -1;
}

void *sv_start_i(void *arg)
{
  server_t *sv = (server_t *) arg;
  sv->start(sv);
}

/* start sv */
void sv_start(server_t *sv)
{
  SERVER_CHECK(sv);
  sv->running_status = 1;
  sv->run(sv);
}

/* stop sv */
void sv_stop(server_t *sv)
{
  SERVER_CHECK(sv);
  sv->running_status = 0;
  DEBUG_LOG(sv->log, "terminating server now");
  sv->terminate(sv);
  sv->clean(&sv);
}

/* terminate sv */
void sv_terminate(server_t *sv)
{
  int i = 0;
  thread_t *pth = NULL;

  SERVER_CHECK(sv);
  sv->running_status = 0;
  /* close server tcp socket */
  if (sv->tcp_set.sockfd > 0) {
    shutdown(sv->tcp_set.sockfd, SHUT_RDWR);
    close(sv->tcp_set.sockfd);
    sv->tcp_set.sockfd = 0;
  }
  /* close server udp socket */
  if (sv->udp_set.sockfd > 0) {
    shutdown(sv->udp_set.sockfd, SHUT_RDWR);
    close(sv->udp_set.sockfd);
    sv->udp_set.sockfd = 0;
  }
  /* close threads */
  for (i = 0; i < sv->max_threads; i++) {
    if ((pth = sv->threads[i]) != NULL) {
      pth->terminate(pth);
      if (pthread_join(pth->thread_id, NULL) == 0) {
        DEBUG_LOG(sv->log, "terminated thread[%u]", pth->thread_id);
      }
      sv->running_threads--;
    }
  }
}

/* clean sv */
void sv_clean(server_t **sv)
{
  thread_t *pth = NULL;
  message_t *msg;

  int i = 0;
  if ((*sv)) {
    /* clean threads */
    if ((*sv)->threads) {
      for (i = 0; i < (*sv)->max_threads; i++) {
        if ((pth = (*sv)->threads[i]) != NULL) {
          pth->clean(&pth);
          (*sv)->threads[i] = NULL;
        }
      }
      free((*sv)->threads);
      (*sv)->threads = NULL;
    }

    /* clean message_queue */
    if ((*sv)->message_queue) {
      while ((*sv)->message_queue->total > 0) {
        msg = (message_t *) (*sv)->message_queue->pop((*sv)->message_queue);
        if (msg)
          msg->clean(&msg);
      }
      (*sv)->message_queue->clean(&((*sv)->message_queue));
    }
  
    /* clean event base */
    //if((*sv)->eventbase) event_base_free((*sv)->eventbase);
    if((*sv)->eventbase) (*sv)->eventbase->clean(&((*sv)->eventbase));

    /* clean timer */
    (*sv)->timer->clean(&((*sv)->timer));

    /* clean btree */
    (*sv)->socktree->clean(&((*sv)->socktree), &((*sv)->socktree->root));

    /* clean self */
    free((*sv));
    (*sv) = NULL;
  }
}
