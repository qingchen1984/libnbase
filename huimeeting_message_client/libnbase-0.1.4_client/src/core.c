#include "core.h"

/* initialize message */
message_t *message_init()
{
  message_t *msg = (message_t *) calloc(1, sizeof(message_t));
  if (msg) {
    msg->clean = message_clean;
  }
  return msg;
}

/* clean message */
void message_clean(message_t **msg)
{
  if (*msg)
    free(*msg);
  *msg = NULL;
}
