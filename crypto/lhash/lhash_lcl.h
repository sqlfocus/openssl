/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


struct lhash_node_st {
    void *data;
    struct lhash_node_st *next;
    unsigned long hash;
};

/* hash链表 */
struct lhash_st {
    OPENSSL_LH_NODE **b;        /* 数据, struct lhash_node_st */
    OPENSSL_LH_COMPFUNC comp;
    OPENSSL_LH_HASHFUNC hash;
    unsigned int num_nodes;             /* */
    unsigned int num_alloc_nodes;       /* ->b[]数组大小 */
    unsigned int p;                     /* */
    unsigned int pmax;                  /* */
    unsigned long up_load;      /* load times 256 */
    unsigned long down_load;    /* load times 256 */
    unsigned long num_items;            /* 已插入的数据项数 */
    unsigned long num_expands;          /* 扩充空间次数 */
    unsigned long num_expand_reallocs;  /* 空间重新分配次数，每次增长一倍 */
    unsigned long num_contracts;
    unsigned long num_contract_reallocs;
    unsigned long num_hash_calls;       /* 调用->hash函数的次数 */
    unsigned long num_comp_calls;       /* 调用->comp函数的次数 */
    unsigned long num_insert;           /* 插入次数 */
    unsigned long num_replace;          /* 插入过程中，替换某键的值的次数 */
    unsigned long num_delete;
    unsigned long num_no_delete;
    unsigned long num_retrieve;
    unsigned long num_retrieve_miss;
    unsigned long num_hash_comps;       /* hash值比较次数 */
    int error;
};
