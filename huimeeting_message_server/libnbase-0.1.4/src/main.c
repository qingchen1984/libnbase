#include <signal.h>
#include "ssignal.h"
#include "core.h"
#include "server.h"

int main(int argc, char **argv)
{
  ssignal_t *si = si_init();
  si->block_all_signal(si);

  server_t *sv = server_init();

  sv->server_type = SERVER_NORMAL;
  //sv->log = log_init("/tmp/server_log");
  sv->log = NULL;
  //sv->buf_size = 1024 * 1024 * 8;
  sv->buf_size = 1024 * 1024 * 8;
  sv->max_threads = 8;
  sv->max_connections = 65535;
  sv->heartbeat_interval = 600000000u;
  sv->sleep_usec = 6000u;
  sv->conn_timeout = 600u;
  sv->send_flag = 1;

  sv->tcp_set.sock_t = TCP_T;
  sv->tcp_set.domain = AF_INET;
  sv->tcp_set.family = AF_INET;
  sv->tcp_set.is_broadcast = 0;
  //sv->tcp_set.port = 8001;
  sv->tcp_set.port = 6714;
  sv->init(sv);
  sv->listen_sock_tcp(sv);

  /*
  sv->udp_set.sock_t = UDP_T;
  sv->udp_set.domain = AF_INET;
  sv->udp_set.family = AF_INET;
  sv->udp_set.is_broadcast = 0;
  sv->udp_set.port = 8002;
  sv->listen_sock_udp(sv);

  sv->broadcast_set.sock_t = UDP_T;
  sv->broadcast_set.domain = AF_INET;
  sv->broadcast_set.family = AF_INET;
  sv->broadcast_set.is_broadcast = 1;
  sv->broadcast_set.port = 8003;
  sv->listen_sock_broadcast(sv);
  */

  pthread_t thread;
  pthread_create(&thread, NULL, sv_start_i, (void *) sv);

  //usleep(sv->sleep_usec);

  /*
  int i;
  for(i = 0; i < 2000; i ++) {
    while (1) {

      if (sv->send_flag == 1)
        break;
      //usleep(sv->sleep_usec);
    }
    sv->send_flag = 0;
    sv->push_data(sv, "127.0.0.1", 6714, "abc", 3, TCP_T, 0);
    //sv->push_data(sv, "127.0.0.1", 85, "def", 3, UDP_T, 0);
    //sv->push_data(sv, "127.0.0.1", 86, "ghi", 3, UDP_T, 1);
  }
  */

  si->register_quit_signal(si, SIGINT);
  si->register_quit_signal(si, SIGQUIT);
  si->register_quit_signal(si, SIGTERM);
  si->register_quit_signal(si, SIGHUP);
  si->event_loop(si);
  sv->stop(sv);
}
