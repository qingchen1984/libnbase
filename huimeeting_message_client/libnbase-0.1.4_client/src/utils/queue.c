#include "queue.h"

/* initialize queue */
queue_t *queue_init()
{
  queue_t *queue = (queue_t *) calloc(1, sizeof(queue_t));
  if (queue) {
    queue->push = queue_push;
    queue->pop = queue_pop;
    queue->del = queue_del;
    queue->head = queue_head;
    queue->tail = queue_tail;
    queue->clean = queue_clean;
    pthread_mutex_init(&(queue->mutex), NULL);

  }
  return queue;
}

/* push queue_elem to queue tail */
void queue_push(queue_t *queue, void *data)
{
  if (queue) {
    pthread_mutex_lock(&(queue->mutex));
    if (queue->last) {
      queue->last->next = (queue_elem_t *) calloc(1, sizeof(queue_elem_t));
      queue->last = queue->last->next;
    } else {
      queue->last = (queue_elem_t *) calloc(1, sizeof(queue_elem_t));
      if (queue->first == NULL)
        queue->first = queue->last;
    }
    queue->last->data = data;
    queue->total++;
    pthread_mutex_unlock(&(queue->mutex));
  }
}

/* pop queue_elem data from queue head and free it */
void *queue_pop(queue_t *queue)
{
  void *p = NULL;
  queue_elem_t *elem = NULL;
  if (queue) {
    pthread_mutex_lock(&(queue->mutex));
    if (queue->total > 0 && (elem = queue->first)) {
      p = elem->data;
      if (queue->first == queue->last) {
        queue->first = queue->last = NULL;
      } else {
        queue->first = queue->first->next;
      }
      free(elem);
      queue->total--;
    }
    pthread_mutex_unlock(&(queue->mutex));
  }
  return p;
}

/* delete queue_elem data from queue head and free it */
void queue_del(queue_t *queue)
{
  queue_elem_t *elem = NULL;
  if (queue) {
    pthread_mutex_lock(&(queue->mutex));
    if (queue->total > 0 && (elem = queue->first)) {
      elem = queue->first;
      if (queue->first == queue->last) {
        queue->first = queue->last = NULL;
      } else {
        queue->first = queue->first->next;
      }
      free(elem);
      queue->total--;
    }
    pthread_mutex_unlock(&(queue->mutex));
  }
  return;
}

/* get queue head data don't free */
void *queue_head(queue_t *queue)
{
  void *p = NULL;
  if (queue && queue->first) {
    p = queue->first->data;
  }
  return p;
}

/* get queue tail data don't free */
void *queue_tail(queue_t *queue)
{
  void *p = NULL;
  if (queue && queue->last) {
    p = queue->last->data;
  }
  return p;
}

/* clean queue */
void queue_clean(queue_t **queue)
{
  queue_elem_t *elem = NULL, *p = NULL;
  if (queue) {
    pthread_mutex_lock(&((*queue)->mutex));
    p = elem = (*queue)->first;
    while ((*queue)->total > 0 && elem) {
      elem = elem->next;
      free(p);
      p = elem;
      (*queue)->total--;
    }
    pthread_mutex_unlock(&((*queue)->mutex));
    pthread_mutex_destroy(&((*queue)->mutex));
    free((*queue));
    (*queue) = NULL;
  }
}

#ifdef _DEBUG_QUEUE
int main()
{
  void *s = NULL;
  int size = 1024;
  char buf[size][8];
  int n = 0;
  int i = 0, j = 0;
  queue_t *queue = queue_init();
  if (queue) {
    for (i = 0; i < size; i++) {
      n = sprintf(buf[i], "%d", i);
      queue->push(queue, buf[i]);
      if ((i % 5) == 0) {
        fprintf(stdout, "id:%d => data:%s\n", j++, (char *) queue->pop(queue));
        fprintf(stdout, "head:%s => tail:%s\n", (char *) (queue->head(queue)),
            (char *) (queue->tail(queue)));
        QUEUE_VIEW(queue);
      }
    }
    QUEUE_VIEW(queue);
    queue->clean(&queue);
  }
}
#endif // _DEBUG_QUEUE
