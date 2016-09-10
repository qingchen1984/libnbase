#ifndef _LOG_H
#define _LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifndef _TYPEDEF_LOG
#define _TYPEDEF_LOG

#define LOG_FILENAME_LIMIT 1024
#define LOG_LINE_LIMIT 8192
#define __DEBUG__ 0
#define	__WARN__ 1
#define	__ERROR__ 2
#define	__FATAL__ 3

static char *_log_level_s[] = { "DEBUG", "WARN", "ERROR", "FATAL" };
static char *ymonths[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
    "Aug", "Sep", "Oct", "Nov", "Dec" };

typedef struct _log
{
  char file[LOG_FILENAME_LIMIT];
  int fd;
  pthread_mutex_t mutex;

  void (*add)(struct _log *, char *, int, const char *, int, char *format, ...);
  void (*close)(struct _log *);
} log_t;

/* initialize log */
log_t *log_init(char *logfile);

#endif // _TYPEDEF_LOG

/* add log */
void log_add(log_t *, char *, int, const char *, int, char *format, ...);

/* close log */
void log_close(log_t *);

#define DEBUG_LOG(log, format...)if(log){log->add(log, __FILE__, __LINE__, __func__, __DEBUG__,format);}
#define WARN_LOG(log, format...)if(log){log->add(log, __FILE__, __LINE__, __func__, __WARN__,format);}
#define ERROR_LOG(log, format...)if(log){log->add(log, __FILE__, __LINE__, __func__,  __ERROR__,format);}
#define FATAL_LOG(log, format...)if(log){log->add(log, __FILE__, __LINE__, __func__, __FATAL__,format);}

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _LOG_H
