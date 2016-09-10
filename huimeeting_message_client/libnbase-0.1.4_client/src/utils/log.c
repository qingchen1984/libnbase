#include "log.h"

/* initialize log */
log_t *log_init(char *logfile)
{
  log_t *log = (log_t *) calloc(1, sizeof(log_t));
  if (log) {
    log->add = log_add;
    log->close = log_close;
    if (logfile) {
      strcpy(log->file, logfile);

      pthread_mutex_init(&(log->mutex), NULL);
      if ((log->fd = open(log->file, O_CREAT | O_WRONLY | O_APPEND, 0644))
          <= 0) {
        fprintf(stderr, "fatal:open log file[%s]  failed, %s", logfile,
            strerror(errno));
        log->close(log);
      }
    } else {
      log->fd = 1;
    }
  }
  return log;
}

/* add log */
void log_add(log_t *log, char *__file__, int __line__, const char* __FUNC__,
    int __level__, char *format, ...)
{
  va_list ap;
  char buf[LOG_LINE_LIMIT];
  char *s = buf;
  struct timeval tv;
  time_t timep;
  struct tm *p = NULL;
  int n = 0;
  if (log) {
    pthread_mutex_lock(&(log->mutex));
    if (log->fd) {
      gettimeofday(&tv, NULL);
      time(&timep);
      p = localtime(&timep);
      n = sprintf(s,
          "[%02d/%s/%04d:%02d:%02d:%02d +%06u] [%04x/%08x] #%s::%d::%s# \"%s:",
          p->tm_mday, ymonths[p->tm_mon], (1900 + p->tm_year), p->tm_hour,
          p->tm_min, p->tm_sec, (size_t) tv.tv_usec, (size_t) getpid(),
          (size_t) pthread_self(), __file__, __line__, __FUNC__,
          _log_level_s[__level__]);
      s += n;
      va_start(ap, format);
      n = vsprintf(s, format, ap);
      va_end(ap);
      s += n;
      n = sprintf(s, "\"\n");
      s += n;
      n = s - buf;
      if (write(log->fd, buf, n) != n) {
        fprintf(stderr, "fatal:writting log failed, %s", strerror(errno));
        close(log->fd);
        log->fd = 0;
      }
    }

    pthread_mutex_unlock(&(log->mutex));
  }
}

/* close log */
void log_close(log_t *log)
{
  if (log) {
    if (log->fd > 0)
      close(log->fd);
    pthread_mutex_destroy(&(log->mutex));
    free(log);
    log = NULL;
  }
}

#ifdef _DEBUG_LOG
int main()
{
  LOG *log = log_init("/tmp/test.log");
  if (log) {
    DEBUG_LOG(log, "调试信息 %s", "DEBUG");
    WARN_LOG(log, "警告信息 %s", "WARN");
    ERROR_LOG(log, "错误信息 %s", "ERROR");
    FATAL_LOG(log, "致命信息 %s", "FATAL");
    /*
       log->add(log, __FILE__, __LINE__, __DEBUG__, "调试信息 %s", "OK");
       log->add(log, __FILE__, __LINE__, __WARN__, "警告信息 %s", "WARN");
       log->add(log, __FILE__, __LINE__, __ERROR__, "错误信息 %s", "ERROR");
       log->add(log, __FILE__, __LINE__, __FATAL__, "致命信息 %s", "FATAL");
       */
    log->close(log);
  }
}
#endif // _DEBUG_LOG
