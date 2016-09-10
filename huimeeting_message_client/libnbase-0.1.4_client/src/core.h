#ifndef _CORE_H
#define _CORE_H

#include <netdb.h>

#include <evbase.h>

#include "btree.h"
#include "utils/log.h"
#include "utils/chunk.h"
#include "utils/timer.h"

/*
#include <android/log.h>
#define  LOG_TAG    "HuikorSP"
#define  LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)
*/

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

  /* inet */
#define TCP_T SOCK_STREAM
#define UDP_T SOCK_DGRAM
#define DGRAM_SIZE 1024
#define	BUF_SIZE 1024 * 1024

  /* message action id define */
#define MESSAGE_QUIT 0x00
#define MESSAGE_NEW_SESSION 0x01
#define MESSAGE_INPUT 0x02
#define MESSAGE_OUTPUT 0x04
#define MESSAGE_PUSH_DATA 0x08

#define MESSAGE_ECHO_ALL 0x00
#define MESSAGE_ECHO_TCP 0x01

  /* server type */
#define SERVER_NORMAL 0x01
#define SERVER_FILE 0x02
#define SERVER_CHUNK 0x04

  /* transaction state */
#ifndef TRANSACTION_STATES
#define READY_STATE 0x00
#define READ_CHUNK_STATE 0x02
#define WRITE_STATE 0x04
#define PACKET_HANDLING_STATE 0x08
#define DATA_HANDLING_STATE 0x10
#define CLOSED_STATE 0x12
#define TRANSACTION_STATES (READY_STATE | READ_CHUNK_STATE | WRITE_STATE \
    | PACKET_HANDLING_STATE | DATA_HANDLING_STATE | CLOSED_STATE)
#endif // TRANSACTION_STATES

  /* handler */
  typedef void handler_t;

  typedef struct _message
  {
    int msg_id;
    int fd;
    int sock_t;
    uint8_t send_crc32[16];
    uint8_t recv_crc32[16];
    uint8_t data[1024];
    int  data_size;
    struct sockaddr_in sa;
    void *handler;

    void (*clean)(struct _message **);
  } message_t;

  message_t *message_init();

  /* clean message */
  void message_clean(message_t **msg);

#define MESSAGE_SIZE sizeof(message_t)

#define MSG_INFO "HUIMEETING"
#define WAN_MESSAGE_SERVER_IP "124.127.250.181"
//#define WAN_MESSAGE_SERVER_IP "127.0.0.1"

  typedef struct _default_head
  {
    uint32_t data_len;
  } default_head_t;

  typedef struct _wan_head
  {
    uint32_t data_len;
    uint8_t  send_crc32[16];
    uint8_t  recv_crc32[16];
    uint8_t  msg_info[16];
    uint8_t  empty[12];
  } wan_head_t;

#define HEAD_SIZE sizeof(default_head_t)
#define WAN_HEAD_SIZE sizeof(wan_head_t)

  struct _server;
  struct _thread;
  struct _session;
  struct _queue;
  struct _buffer;

  typedef struct _baseset
  {
    int sockfd;
    int sock_t;
    char *host;
    int domain;
    int family;
    int is_broadcast;
    int port;
    int backlog;
    struct sockaddr_in sa;
    //struct event event;
    EVENT *event;
  } baseset_t;

  typedef struct _server
  {
    /* base setting */
    int running_status;
    struct _baseset tcp_set;
    struct _baseset udp_set;
    struct _baseset broadcast_set;

    int send_flag;
    /* mutex setting */
    pthread_mutex_t mutex;

    char dest_port[8];
    char dest_host[64];

    int32_t tcp_num;
    int32_t udp_num;
    int32_t broadcast_num;

    /* global log pointer */
    log_t *log;

    /* timer */
    base_timer_t *timer;

    /* server type */
    int server_type;

    int buf_size;

    /* usleep setting*/
    uint32_t heartbeat_interval;
    uint32_t sleep_usec;
    uint32_t conn_timeout;

    btree_t *socktree;

    /* heartbeat handler */
    void (*heartbeat_handler)(void);

    /* thread setting */
    int max_threads; /* max thread limitation */
    int running_threads;
    struct _thread **threads; /* point to threads pool */

    /* message queue setting */
    struct _queue *message_queue;

    /* event setting */
    //struct event_base *eventbase;
    EVBASE *eventbase;

    /* connection setting */
    int max_connections; /* max connection limitation */
    int running_connections; /* connection number */

    /* methods */
    void (*start)(struct _server *);
    void (*stop)(struct _server *);
    void (*event_handler)(int, short, void *);
    int (*init)(struct _server *);
    int (*listen_sock_tcp)(struct _server *);
    int (*listen_sock_udp)(struct _server *);
    int (*listen_sock_broadcast)(struct _server *);
    int (*init_socket)(struct _server *, char *, int, int, int);
    int (*push_data)(struct _server *, char *, int, char *, int, int, int);
    int (*terminate_node)(struct _server *, char *, int, int, int);
    void (*message_echo_all)(struct _server *, char *, int);
    void (*message_echo_tcp)(struct _server *, char *, int, char *);
    void (*run)(struct _server *);
    int (*addconn)(struct _server *, int, int, struct sockaddr_in *);
    void (*terminate)(struct _server *);
    void (*clean)(struct _server **);
  } server_t;

  typedef struct _thread
  {
    /* server pointer and hook */
    struct _server *sv;

    /* global log pointer */
    log_t *log;

    /* base setting */
    pthread_mutex_t mutex;
    int index; /* index id in threads pool */
    pthread_t thread_id; /* thread_id */
    int running_status; /* show running status*/

    /* libevent */
    //struct event_base *eventbase;
    EVBASE *eventbase;

    /* message queue setting */
    struct _queue *message_queue;

    /* session setting */
    struct _session **sessions;

    /* timer */
    base_timer_t *timer;

    /* methods */
    /* thread event handler */
    void (*event_handler)(int, short, void *);
    void *(*run)(void *);
    int (*addconn)(struct _thread *, int, int, struct sockaddr_in *);
    int (*add_session)(struct _thread *, int, int, struct sockaddr_in *);
    int (*push_data)(struct _thread *, int, char *, int);
    void (*terminate_session)(struct _thread *, struct _session *);
    void (*state_conns)(struct _thread *);
    void (*terminate)(struct _thread *);
    void (*clean)(struct _thread **);
  } thread_t;

  typedef struct _session
  {
    /* thread pointer */
    struct _thread *pth;

    /* base setting */
    int fd;
    int sock_t;
    struct sockaddr_in tcp_sa;
    int crc32_flag;
    uint8_t send_crc32[16];

    /* udp sockaddr_in */
    struct sockaddr_in udp_sa;

    /* packet setting */
    uint16_t head_readed_bytes;
    char packet_head_buffer[HEAD_SIZE];
    char packet_wan_head_buffer[WAN_HEAD_SIZE];
    uint32_t body_readed_bytes;

    /* global log pointer */
    log_t *log;

    /* timer */
    base_timer_t *timer;

    /* transaction  */
    chunk_t *chunk;
    int transaction_state;
    unsigned long transaction_id;

    /* bytes total  */
    uint64_t send_total;
    uint64_t recv_total;

    /* buffer setting */
    struct _buffer *buffer; /* point to buffer */
    int buf_size; /* max length of buffer */

    /* event setting */
    //struct event event;
    EVENT *event;
    int event_flags;

    /* queue setting */
    struct _queue *send_queue;

    int (*set)(struct _session *, int, int, struct sockaddr_in *);
    void (*event_handler)(int, short, void *);
    int (*event_update)(struct _session *, short);
    int (*read_handler)(struct _session *);
    int (*write_handler)(struct _session *);
    int (*state_handler)(struct _session *);
    void (*push_message)(struct _session *, int);
    int (*push_chunk)(struct _session *, void *, size_t);
    int (*push_file)(struct _session *, char *, uint64_t, uint64_t);
    int (*terminate)(struct _session *);
    void (*clean)(struct _session **);
    int (*parse_packet)(struct _session *);
    int (*parse_packet_wan)(struct _session *);
  } session_t;

#define _ERROR_LOG(format...) \
{ \
  fprintf(stderr, "[%s:%d] ", __FILE__, __LINE__); \
  fprintf(stderr, "\""); \
  fprintf(stderr, format); \
  fprintf(stderr, "\""); \
  fprintf(stderr, "\n"); \
}

#define _DEBUG_LOG(format...) \
{ \
  fprintf(stdout, "[%s:%d] ", __FILE__, __LINE__); \
  fprintf(stdout, "\""); \
  fprintf(stdout, format); \
  fprintf(stdout, "\""); \
  fprintf(stdout, "\n"); \
}

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _CORE_H
