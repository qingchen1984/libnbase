#ifndef _BTREE_H
#define _BTREE_H

#include <stdint.h>

typedef uint8_t nodekey_t;

typedef struct _node
{
  uint8_t host[64];
  nodekey_t *key;
  int32_t sockfd;
  struct _node *left;
  struct _node *right;
  struct _node *parent;
} node_t;

typedef struct _btree
{
  node_t *root;

  void (*inseart)(struct _btree *, node_t **, node_t *, nodekey_t *);
  node_t *(*search)(struct _btree *, node_t *, nodekey_t *);
  node_t *(*search_min)(struct _btree *, node_t *);
  node_t *(*search_max)(struct _btree *, node_t *);
  node_t *(*search_predecessor)(struct _btree *, node_t *);
  node_t *(*search_successor)(struct _btree *, node_t *);
  int32_t (*delete_node)(struct _btree *, node_t **, nodekey_t *);
  void (*create)(struct _btree *, node_t **, int32_t, nodekey_t *);
  node_t *(*create_node)();
  void (*clean_all_node)(struct _btree *, node_t *);
  void (*clean)(struct _btree **, node_t **);
} btree_t;

btree_t *tr_init();

void tr_inseart(btree_t *, node_t **, node_t *, nodekey_t *);

node_t *tr_search(btree_t *, node_t *, nodekey_t *);

node_t *tr_search_min(btree_t *, node_t *);

node_t *tr_search_max(btree_t *, node_t *);

node_t *tr_search_predecessor(btree_t *, node_t *);

node_t *tr_search_successor(btree_t *, node_t *);

int32_t tr_delete_node(btree_t *, node_t **, nodekey_t *);

void tr_create(btree_t *, node_t **, int32_t, nodekey_t *);

node_t *tr_create_node();

void tr_clean_all_node(btree_t *, node_t *);

void tr_clean(btree_t **, node_t **);

#endif // _BTREE_H
