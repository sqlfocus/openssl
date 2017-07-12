/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/numbers.h"
#include <openssl/stack.h>
#include <openssl/objects.h>

/* openssl内部使用的堆栈结构 */
struct stack_st {
    int num;                    /* 压栈个数 */
    const char **data;          /* 压栈数据指针数组 */
    int sorted;                 /* 是否排序? */
    size_t num_alloc;           /* ->data[]大小 */
    OPENSSL_sk_compfunc comp;   /* 比较函数，用于压栈数据排序 */
};

#undef MIN_NODES
#define MIN_NODES       4       /* 栈最少元素个数 */

#include <errno.h>

/* 设置排序函数 */
OPENSSL_sk_compfunc OPENSSL_sk_set_cmp_func(OPENSSL_STACK *sk, OPENSSL_sk_compfunc c)
{
    OPENSSL_sk_compfunc old = sk->comp;

    if (sk->comp != c)
        sk->sorted = 0;
    sk->comp = c;

    return old;
}

/* 栈复制 */
OPENSSL_STACK *OPENSSL_sk_dup(const OPENSSL_STACK *sk)
{
    OPENSSL_STACK *ret;

    if (sk->num < 0)
        return NULL;

    if ((ret = OPENSSL_malloc(sizeof(*ret))) == NULL)
        return NULL;

    /* direct structure assignment */
    *ret = *sk;

    if ((ret->data = OPENSSL_malloc(sizeof(*ret->data) * sk->num_alloc)) == NULL)
        goto err;
    memcpy(ret->data, sk->data, sizeof(char *) * sk->num);
    return ret;
 err:
    OPENSSL_sk_free(ret);
    return NULL;
}

/* 栈深度复制，包括数据；事先不知道具体的数据类型，因此需要提供数据复制函数指针 */
OPENSSL_STACK *OPENSSL_sk_deep_copy(const OPENSSL_STACK *sk,
                             OPENSSL_sk_copyfunc copy_func,
                             OPENSSL_sk_freefunc free_func)
{
    OPENSSL_STACK *ret;
    int i;

    if (sk->num < 0)
        return NULL;

    if ((ret = OPENSSL_malloc(sizeof(*ret))) == NULL)
        return NULL;

    /* direct structure assignment */
    *ret = *sk;

    ret->num_alloc = sk->num > MIN_NODES ? (size_t)sk->num : MIN_NODES;
    ret->data = OPENSSL_zalloc(sizeof(*ret->data) * ret->num_alloc);
    if (ret->data == NULL) {
        OPENSSL_free(ret);
        return NULL;
    }

    for (i = 0; i < ret->num; ++i) {    /* 复制数据 */
        if (sk->data[i] == NULL)
            continue;
        if ((ret->data[i] = copy_func(sk->data[i])) == NULL) {
            while (--i >= 0)
                if (ret->data[i] != NULL)
                    free_func((void *)ret->data[i]);
            OPENSSL_sk_free(ret);
            return NULL;
        }
    }
    return ret;
}

/* 创建无序栈 */
OPENSSL_STACK *OPENSSL_sk_new_null(void)
{
    return OPENSSL_sk_new((OPENSSL_sk_compfunc)NULL);
}

/* 创建排序栈 */
OPENSSL_STACK *OPENSSL_sk_new(OPENSSL_sk_compfunc c)
{
    OPENSSL_STACK *ret;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL)
        goto err;
    if ((ret->data = OPENSSL_zalloc(sizeof(*ret->data) * MIN_NODES)) == NULL)
        goto err;
    ret->comp = c;
    ret->num_alloc = MIN_NODES;
    return (ret);

 err:
    OPENSSL_free(ret);
    return (NULL);
}

/* 入栈；@param loc: 插入位置或负数(正常压栈) */
int OPENSSL_sk_insert(OPENSSL_STACK *st, const void *data, int loc)
{
    if (st == NULL || st->num < 0 || st->num == INT_MAX) {
        return 0;
    }

    if (st->num_alloc <= (size_t)(st->num + 1)) {
        size_t doub_num_alloc = st->num_alloc * 2;
        const char **tmpdata;

        /* Overflow checks */
        if (doub_num_alloc < st->num_alloc)
            return 0;

        /* Avoid overflow due to multiplication by sizeof(char *) */
        if (doub_num_alloc > SIZE_MAX / sizeof(char *))
            return 0;

        tmpdata = OPENSSL_realloc((char *)st->data,
                                  sizeof(char *) * doub_num_alloc);
        if (tmpdata == NULL)
            return 0;

        st->data = tmpdata;
        st->num_alloc = doub_num_alloc;
    }
    if ((loc >= st->num) || (loc < 0)) {  /* 压栈 */
        st->data[st->num] = data;
    } else {                              /* 插入 */
        memmove(&st->data[loc + 1], &st->data[loc],
                sizeof(st->data[0]) * (st->num - loc));
        st->data[loc] = data;
    }
    st->num++;                            /* 调整计数 */
    st->sorted = 0;
    return st->num;                       /* 返回计数值 */
}

/* 删除栈元素，根据数据指针删除 */
void *OPENSSL_sk_delete_ptr(OPENSSL_STACK *st, const void *p)
{
    int i;

    for (i = 0; i < st->num; i++)
        if (st->data[i] == p)
            return OPENSSL_sk_delete(st, i);
    return NULL;
}

/* 删除栈元素，根据位置删除 */
void *OPENSSL_sk_delete(OPENSSL_STACK *st, int loc)
{
    const char *ret;

    if (st == NULL || loc < 0 || loc >= st->num)
        return NULL;

    ret = st->data[loc];
    if (loc != st->num - 1)
         memmove(&st->data[loc], &st->data[loc + 1],
                 sizeof(st->data[0]) * (st->num - loc - 1));
    st->num--;
    return (void *)ret;     /* 返回删除的元素 */
}

/* 查找辅助函数 */
static int internal_find(OPENSSL_STACK *st, const void *data,
                         int ret_val_options)
{
    const void *r;
    int i;

    if (st == NULL)
        return -1;

    if (st->comp == NULL) {  /* 无排序函数，匹配数据地址 */
        for (i = 0; i < st->num; i++)
            if (st->data[i] == data)
                return (i);
        return (-1);
    }
    OPENSSL_sk_sort(st);     /* 排序 */
    if (data == NULL)
        return (-1);         /* 二分查找 */
    r = OBJ_bsearch_ex_(&data, st->data, st->num, sizeof(void *), st->comp,
                        ret_val_options);
    if (r == NULL)
        return (-1);         /* 返回偏移，即元素的索引 */
    return (int)((const char **)r - st->data);
}

/* 返回第一个匹配 */
int OPENSSL_sk_find(OPENSSL_STACK *st, const void *data)
{
    return internal_find(st, data, OBJ_BSEARCH_FIRST_VALUE_ON_MATCH);
}
/* 如果未匹配，则返回最后用于匹配算法的数据 */
int OPENSSL_sk_find_ex(OPENSSL_STACK *st, const void *data)
{
    return internal_find(st, data, OBJ_BSEARCH_VALUE_ON_NOMATCH);
}

/* 数据压栈 */
int OPENSSL_sk_push(OPENSSL_STACK *st, const void *data)
{
    return (OPENSSL_sk_insert(st, data, st->num));
}
/* 数据插入栈顶 */
int OPENSSL_sk_unshift(OPENSSL_STACK *st, const void *data)
{
    return (OPENSSL_sk_insert(st, data, 0));
}
/* 移除栈顶 */
void *OPENSSL_sk_shift(OPENSSL_STACK *st)
{
    if (st == NULL)
        return (NULL);
    if (st->num <= 0)
        return (NULL);
    return (OPENSSL_sk_delete(st, 0));
}

/* 出栈 */
void *OPENSSL_sk_pop(OPENSSL_STACK *st)
{
    if (st == NULL)
        return (NULL);
    if (st->num <= 0)
        return (NULL);
    return (OPENSSL_sk_delete(st, st->num - 1));
}

/* 清空栈结构，并不释放压栈数据 */
void OPENSSL_sk_zero(OPENSSL_STACK *st)
{
    if (st == NULL)
        return;
    if (st->num <= 0)
        return;
    memset(st->data, 0, sizeof(*st->data) * st->num);
    st->num = 0;
}

/* 清空栈，并释放压栈数据 */
void OPENSSL_sk_pop_free(OPENSSL_STACK *st, OPENSSL_sk_freefunc func)
{
    int i;

    if (st == NULL)
        return;
    for (i = 0; i < st->num; i++)
        if (st->data[i] != NULL)
            func((char *)st->data[i]);
    OPENSSL_sk_free(st);
}

/* 释放栈自身内存 */
void OPENSSL_sk_free(OPENSSL_STACK *st)
{
    if (st == NULL)
        return;
    OPENSSL_free(st->data);
    OPENSSL_free(st);
}

int OPENSSL_sk_num(const OPENSSL_STACK *st)
{
    if (st == NULL)
        return -1;
    return st->num;
}

/* 按索引提取压栈数据 */
void *OPENSSL_sk_value(const OPENSSL_STACK *st, int i)
{
    if (st == NULL || i < 0 || i >= st->num)
        return NULL;
    return (void *)st->data[i];
}

/* 按索引设置栈数据 */
void *OPENSSL_sk_set(OPENSSL_STACK *st, int i, const void *data)
{
    if (st == NULL || i < 0 || i >= st->num)
        return NULL;
    st->data[i] = data;
    return (void *)st->data[i];
}

/* 排序 */
void OPENSSL_sk_sort(OPENSSL_STACK *st)
{
    if (st && !st->sorted && st->comp != NULL) {
        qsort(st->data, st->num, sizeof(char *), st->comp);
        st->sorted = 1;   /* 参考man qsort；从栈顶起，升序排序 */
    }
}
int OPENSSL_sk_is_sorted(const OPENSSL_STACK *st)
{
    if (st == NULL)
        return 1;
    return st->sorted;
}
