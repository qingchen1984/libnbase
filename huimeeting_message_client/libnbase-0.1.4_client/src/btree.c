#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "btree.h"
#include "core.h"

btree_t *tr_init()
{
  btree_t *tr = (btree_t *) calloc(1, sizeof(btree_t));
  tr->inseart = tr_inseart;
  tr->search = tr_search;
  tr->search_min = tr_search_min;
  tr->search_max = tr_search_max;
  tr->search_predecessor = tr_search_predecessor;
  tr->search_successor = tr_search_successor;
  tr->delete_node = tr_delete_node;
  tr->create = tr_create;
  tr->create_node = tr_create_node;
  tr->clean_all_node = tr_clean_all_node;
  tr->clean = tr_clean;
  tr->root = NULL;

  return tr;
}

void tr_inseart(btree_t *tr, node_t **root, node_t *node, nodekey_t *key)
{
  node_t *p = node;
  p->key = key;
  p->left = p->right = p->parent = NULL;

  if (*root == NULL) {
    *root = p;
    return;
  }

  int32_t ret;
  ret = strcmp((*root)->key, key);
  //LOGI("@tim inseart strcmp %s %s %d \n", (*root)->key, key, ret);
  if ((*root)->left == NULL && ret > 0) {
    p->parent = *root;
    (*root)->left = p;
    //LOGI("@tim inseart left %s %d \n", (*root)->left->key, (*root)->left->sockfd);
    return;
  }

  if ((*root)->right == NULL && ret < 0) {
    p->parent = *root;
    (*root)->right = p;
    //LOGI("@tim inseart right %s %d \n", (*root)->right->key, (*root)->right->sockfd);
    return;
  }

  if (ret > 0)
    tr->inseart(tr, &(*root)->left, p, key);
  else if (ret < 0)
    tr->inseart(tr, &(*root)->right, p, key);
  else
    return;
}

node_t *tr_search(btree_t *tr, node_t *root, nodekey_t *key)
{
  if (root == NULL) {
    //LOGI("@tim root == NULL return \n");
    return NULL;
  }

  int32_t ret;
  ret = strcmp(key, root->key);
  //printf("key %s root->key %s ret %d \n", key, root->key, ret);
  //LOGI("@tim search strcmp ret %s %s %d \n", key, root->key, ret);
  if (ret > 0)
    return tr->search(tr, root->right, key);
  else if (ret < 0)
    return tr->search(tr, root->left, key);
  else {
    //LOGI("@tim search node return %s %d \n", root->key, root->sockfd);
    return root;
  }
}

node_t *tr_search_min(btree_t *tr, node_t *root)
{
  if (root == NULL)
    return NULL;
  if (root->left == NULL)
    return root;
  else
    return tr->search_min(tr, root->left);
}

node_t *tr_search_max(btree_t *tr, node_t *root)
{
  if (root == NULL)
    return NULL;
  if (root->right == NULL)
    return root;
  else
    return tr->search_max(tr, root->right);
}

// 查找结点的前驱
node_t *tr_search_predecessor(btree_t *tr, node_t *p)
{
  if (p == NULL)
    return p;
  if (p->left) {
    return tr->search_max(tr, p->left);
  } else {
    while (p->parent) {
      if (p->parent->right == p)
        break;
      p = p->parent;
    }
    return p->parent;
  }
}

// 查找结点的后继
node_t *tr_search_successor(btree_t *tr, node_t *p)
{
  if (p == NULL)
    return p;
  if (p->right) {
    return tr->search_min(tr, p->right);
  } else {
    while (p->parent) {
      if (p->parent->left == p)
        break;
      p = p->parent;
    }
    return p->parent;
  }
}

int32_t tr_delete_node(btree_t *tr, node_t **root, nodekey_t *key)
{
  node_t *node_ret;
  int32_t   tmp_sockfd = 0;
  uint8_t   tmp_host[32] = {0};

  node_t *p = tr->search(tr, *root, key);
  /*
  LOGI("@tim key %s, root node %s %d, search node %s %d \n", key, (*root)->key, (*root)->sockfd, 
      p->key, p->sockfd);
      */
  if (!p)
    return 0;
  if (p->left == NULL && p->right == NULL) {
    if (p->parent == NULL) {
      free(p);
      *root = NULL;
    } else {
      if (p->parent->left == p)
        p->parent->left = NULL;
      else
        p->parent->right = NULL;
      free(p);
    }
  } else if (p->left && !(p->right)) {
    p->left->parent = p->parent;
    if (p->parent == NULL)
      *root = p->left;
    else if (p->parent->left == p)
      p->parent->left = p->left;
    else
      p->parent->right = p->left;
    free(p);
  } else if (p->right && !(p->left)) {
    p->right->parent = p->parent;
    if (p->parent == NULL)
      *root = p->right;
    else if (p->parent->left == p)
      p->parent->left = p->right;
    else
      p->parent->right = p->right;
    free(p);
  } else {
    /*
    LOGI("@tim key %s, root node %s %d, root left node %s %d \n", key, (*root)->key, (*root)->sockfd, 
        (*root)->left->key, (*root)->left->sockfd);
    LOGI("@tim key %s, root node %s %d, search right node %s %d \n", key, (*root)->key, (*root)->sockfd, 
        p->right->key, p->right->sockfd);
        */
    node_ret = tr->search_successor(tr, p);
    // 更新key sockfd
    //LOGI("delete successor node key sockfd %s %d \n", node_ret->key, node_ret->sockfd);
    tmp_sockfd = node_ret->sockfd;
    memcpy((void *) tmp_host, (void *) node_ret->key, strlen(node_ret->key));
    tr->delete_node(tr, root, node_ret->key);

    memset(p->host, 0, sizeof(p->host));
    memcpy((void *) p->host, (void *) tmp_host, sizeof(tmp_host));
    p->sockfd = tmp_sockfd;
    p->key = p->host;
    //LOGI("update node key sockfd %s %d \n", p->key, p->sockfd);
  }
  return 1;
}

node_t *tr_create_node()
{
  node_t *p = (node_t *) malloc(sizeof(node_t));
  return p;
}

void tr_clean_all_node(btree_t *tr, node_t *root)
{
  if (root == NULL)
    return;
  tr->clean_all_node(tr, root->left);
  tr->clean_all_node(tr, root->right);
  free(root);
}

void tr_create(btree_t *tr, node_t **root, int32_t sockfd, nodekey_t *key)
{
  node_t *p = tr->create_node();
  p->sockfd = sockfd;
  memset(p->host, 0, sizeof(p->host));
  memcpy((void *) p->host, (void *) key, strlen(key));
  tr->inseart(tr, root, p, p->host);
}

void tr_clean(btree_t **tr, node_t **root)
{
  (*tr)->clean_all_node(*tr, *root);
  *root = NULL;
  free(*tr);
  *tr = NULL;
}
