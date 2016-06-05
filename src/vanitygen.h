/*
 * vanitygen is based on:
 *
 * Vanitygen, vanity bitcoin address generator
 * Copyright (C) 2011 <samr7@cs.washington.edu>
 * Copyright (C) 2016 Strength in Numbers Foundation
 *
 * Vanitygen is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version. 
 *
 * Vanitygen is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Vanitygen.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef VANITYGEN_H
#define VANITYGEN_H

#include <stdio.h>
#include <stdint.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <pthread.h>

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include <time.h>

#define INLINE
#define snprintf _snprintf

struct timezone;

extern int gettimeofday(struct timeval *tv, struct timezone *tz);
extern void timeradd(struct timeval *a, struct timeval *b,
             struct timeval *result);
extern void timersub(struct timeval *a, struct timeval *b,
             struct timeval *result);

extern TCHAR *optarg;
extern int optind;

extern int getopt(int argc, TCHAR *argv[], TCHAR *optstring);

extern int count_processors(void);

#define PRSIZET "I"

static inline char *
strtok_r(char *strToken, const char *strDelimit, char **context) {
    return strtok_s(strToken, strDelimit, context);
}
#else
#define INLINE inline
#define PRSIZET "z"
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#endif


extern const char *vg_b58_alphabet;
extern const signed char vg_b58_reverse_map[256];

extern void fdumphex(FILE *fp, const unsigned char *src, size_t len);
extern void fdumpbn(FILE *fp, const BIGNUM *bn);
extern void dumphex(const unsigned char *src, size_t len);
extern void dumpbn(const BIGNUM *bn);

extern void vg_b58_encode_check(void *buf, size_t len, char *result);
extern int vg_b58_decode_check(const char *input, void *buf, size_t len);

extern void vg_encode_address(const EC_POINT *ppoint, const EC_GROUP *pgroup,
			      int addrtype, char *result);
extern void vg_encode_script_address(const EC_POINT *ppoint,
				     const EC_GROUP *pgroup,
				     int addrtype, char *result);
extern void vg_encode_privkey(const EC_KEY *pkey, int addrtype, char *result);
extern int vg_set_privkey(const BIGNUM *bnpriv, EC_KEY *pkey);
extern int vg_decode_privkey(const char *b58encoded,
			     EC_KEY *pkey, int *addrtype);

enum {
	VG_PROTKEY_DEFAULT = -1,
	VG_PROTKEY_BRIEF_PBKDF2_4096_HMAC_SHA256_AES_256_CBC = 0,
	VG_PROTKEY_PKCS_PBKDF2_4096_HMAC_SHA256_AES_256_CBC = 16,
};

#define VG_PROTKEY_MAX_B58 128

extern int vg_protect_encode_privkey(char *out,
				     const EC_KEY *pkey, int keytype,
				     int parameter_group,
				     const char *pass);
extern int vg_protect_decode_privkey(EC_KEY *pkey, int *keytype,
				     const char *encoded, const char *pass);

extern int vg_pkcs8_encode_privkey(char *out, int outlen,
				   const EC_KEY *pkey,
				   const char *pass);
extern int vg_pkcs8_decode_privkey(EC_KEY *pkey, const char *pem_in,
				   const char *pass);

extern int vg_decode_privkey_any(EC_KEY *pkey, int *addrtype,
				 const char *input, const char *pass);

extern int vg_read_password(char *buf, size_t size);
extern int vg_check_password_complexity(const char *pass, int verbose);

extern int vg_read_file(FILE *fp, char ***result, int *rescount);


#define VANITYGEN_VERSION "0.22"

typedef struct _vg_context_s vg_context_t;

struct _vg_exec_context_s;
typedef struct _vg_exec_context_s vg_exec_context_t;

typedef void *(*vg_exec_context_threadfunc_t)(vg_exec_context_t *);

/* Context of one pattern-matching unit within the process */
struct _vg_exec_context_s {
	vg_context_t			*vxc_vc;
	BN_CTX				*vxc_bnctx;
	EC_KEY				*vxc_key;
	int				vxc_delta;
	unsigned char			vxc_binres[28];
	BIGNUM				vxc_bntarg;
	BIGNUM				vxc_bnbase;
	BIGNUM				vxc_bntmp;
	BIGNUM				vxc_bntmp2;

	vg_exec_context_threadfunc_t	vxc_threadfunc;
	pthread_t			vxc_pthread;
	int				vxc_thread_active;

	/* Thread synchronization */
	struct _vg_exec_context_s	*vxc_next;
	int				vxc_lockmode;
	int				vxc_stop;
};


typedef void (*vg_free_func_t)(vg_context_t *);
typedef int (*vg_add_pattern_func_t)(vg_context_t *,
				     const char ** const patterns,
				     int npatterns);
typedef void (*vg_clear_all_patterns_func_t)(vg_context_t *);
typedef int (*vg_test_func_t)(vg_exec_context_t *);
typedef int (*vg_hash160_sort_func_t)(vg_context_t *vcp, void *buf);
typedef void (*vg_output_error_func_t)(vg_context_t *vcp, const char *info);
typedef void (*vg_output_match_func_t)(vg_context_t *vcp, EC_KEY *pkey,
				       const char *pattern);
typedef void (*vg_output_timing_func_t)(vg_context_t *vcp, double count,
					unsigned long long rate,
					unsigned long long total);

enum vg_format {
	VCF_PUBKEY,
	VCF_SCRIPT,
};

/* Application-level context, incl. parameters and global pattern store */
struct _vg_context_s {
	int			vc_addrtype;
	int			vc_privtype;
	unsigned long		vc_npatterns;
	unsigned long		vc_npatterns_start;
	unsigned long long	vc_found;
	int			vc_pattern_generation;
	double			vc_chance;
	const char		*vc_result_file;
	const char		*vc_key_protect_pass;
	int			vc_remove_on_match;
	int			vc_only_one;
	int			vc_verbose;
	enum vg_format		vc_format;
	int			vc_pubkeytype;
	EC_POINT		*vc_pubkey_base;
	int			vc_halt;

	vg_exec_context_t	*vc_threads;
	int			vc_thread_excl;

	/* Internal methods */
	vg_free_func_t			vc_free;
	vg_add_pattern_func_t		vc_add_patterns;
	vg_clear_all_patterns_func_t	vc_clear_all_patterns;
	vg_test_func_t			vc_test;
	vg_hash160_sort_func_t		vc_hash160_sort;

	/* Performance related members */
	unsigned long long		vc_timing_total;
	unsigned long long		vc_timing_prevfound;
	unsigned long long		vc_timing_sincelast;
	struct _timing_info_s		*vc_timing_head;

	/* External methods */
	vg_output_error_func_t		vc_output_error;
	vg_output_match_func_t		vc_output_match;
	vg_output_timing_func_t		vc_output_timing;
};


/* Base context methods */
extern void vg_context_free(vg_context_t *vcp);
extern int vg_context_add_patterns(vg_context_t *vcp,
				   const char ** const patterns, int npatterns);
extern void vg_context_clear_all_patterns(vg_context_t *vcp);
extern int vg_context_start_threads(vg_context_t *vcp);
extern void vg_context_stop_threads(vg_context_t *vcp);
extern void vg_context_wait_for_completion(vg_context_t *vcp);

/* Prefix context methods */
extern vg_context_t *vg_prefix_context_new(int addrtype, int privtype,
					   int caseinsensitive);
extern void vg_prefix_context_set_case_insensitive(vg_context_t *vcp,
						   int caseinsensitive);
extern double vg_prefix_get_difficulty(int addrtype, const char *pattern);

/* Regex context methods */
extern vg_context_t *vg_regex_context_new(int addrtype, int privtype);

/* Utility functions */
extern int vg_output_timing(vg_context_t *vcp, int cycle, struct timeval *last);
extern void vg_output_match_console(vg_context_t *vcp, EC_KEY *pkey,
				    const char *pattern);
extern void vg_output_timing_console(vg_context_t *vcp, double count,
				     unsigned long long rate,
				     unsigned long long total);



/* Internal vg_context methods */
extern int vg_context_hash160_sort(vg_context_t *vcp, void *buf);
extern void vg_context_thread_exit(vg_context_t *vcp);

/* Internal Init/cleanup for common execution context */
extern int vg_exec_context_init(vg_context_t *vcp, vg_exec_context_t *vxcp);
extern void vg_exec_context_del(vg_exec_context_t *vxcp);
extern void vg_exec_context_consolidate_key(vg_exec_context_t *vxcp);
extern void vg_exec_context_calc_address(vg_exec_context_t *vxcp);
extern EC_KEY *vg_exec_context_new_key(void);

/* Internal execution context lock handling functions */
extern void vg_exec_context_downgrade_lock(vg_exec_context_t *vxcp);
extern int vg_exec_context_upgrade_lock(vg_exec_context_t *vxcp);
extern void vg_exec_context_yield(vg_exec_context_t *vxcp);

#include <assert.h>

/*
 * AVL tree implementation
 */

typedef enum { CENT = 1, LEFT = 0, RIGHT = 2 } avl_balance_t;

typedef struct _avl_item_s {
    struct _avl_item_s *ai_left, *ai_right, *ai_up;
    avl_balance_t ai_balance;
#ifndef NDEBUG
    int ai_indexed;
#endif
} avl_item_t;

typedef struct _avl_root_s {
    avl_item_t *ar_root;
} avl_root_t;

static INLINE void
avl_root_init(avl_root_t *rootp)
{
    rootp->ar_root = NULL;
}

static INLINE int
avl_root_empty(avl_root_t *rootp)
{
    return (rootp->ar_root == NULL) ? 1 : 0;
}

static INLINE void
avl_item_init(avl_item_t *itemp)
{
    itemp->ai_left = NULL;
    itemp->ai_right = NULL;
    itemp->ai_up = NULL;
    itemp->ai_balance = CENT;
#ifndef NDEBUG
    itemp->ai_indexed = 0;
#endif
}

#define container_of(ptr, type, member) \
    (((type*) (((unsigned char *)ptr) - \
           (size_t)&(((type *)((unsigned char *)0))->member))))

#define avl_item_entry(ptr, type, member) \
    container_of(ptr, type, member)



static INLINE void
_avl_rotate_ll(avl_root_t *rootp, avl_item_t *itemp)
{
    avl_item_t *tmp;
    tmp = itemp->ai_left;
    itemp->ai_left = tmp->ai_right;
    if (itemp->ai_left)
        itemp->ai_left->ai_up = itemp;
    tmp->ai_right = itemp;

    if (itemp->ai_up) {
        if (itemp->ai_up->ai_left == itemp) {
            itemp->ai_up->ai_left = tmp;
        } else {
            assert(itemp->ai_up->ai_right == itemp);
            itemp->ai_up->ai_right = tmp;
        }
    } else {
        rootp->ar_root = tmp;
    }
    tmp->ai_up = itemp->ai_up;
    itemp->ai_up = tmp;
}

static INLINE void
_avl_rotate_lr(avl_root_t *rootp, avl_item_t *itemp)
{
    avl_item_t *rcp, *rlcp;
    rcp = itemp->ai_left;
    rlcp = rcp->ai_right;
    if (itemp->ai_up) {
        if (itemp == itemp->ai_up->ai_left) {
            itemp->ai_up->ai_left = rlcp;
        } else {
            assert(itemp == itemp->ai_up->ai_right);
            itemp->ai_up->ai_right = rlcp;
        }
    } else {
        rootp->ar_root = rlcp;
    }
    rlcp->ai_up = itemp->ai_up;
    rcp->ai_right = rlcp->ai_left;
    if (rcp->ai_right)
        rcp->ai_right->ai_up = rcp;
    itemp->ai_left = rlcp->ai_right;
    if (itemp->ai_left)
        itemp->ai_left->ai_up = itemp;
    rlcp->ai_left = rcp;
    rlcp->ai_right = itemp;
    rcp->ai_up = rlcp;
    itemp->ai_up = rlcp;
}

static INLINE void
_avl_rotate_rr(avl_root_t *rootp, avl_item_t *itemp)
{
    avl_item_t *tmp;
    tmp = itemp->ai_right;
    itemp->ai_right = tmp->ai_left;
    if (itemp->ai_right)
        itemp->ai_right->ai_up = itemp;
    tmp->ai_left = itemp;

    if (itemp->ai_up) {
        if (itemp->ai_up->ai_right == itemp) {
            itemp->ai_up->ai_right = tmp;
        } else {
            assert(itemp->ai_up->ai_left == itemp);
            itemp->ai_up->ai_left = tmp;
        }
    } else {
        rootp->ar_root = tmp;
    }
    tmp->ai_up = itemp->ai_up;
    itemp->ai_up = tmp;
}

static INLINE void
_avl_rotate_rl(avl_root_t *rootp, avl_item_t *itemp)
{
    avl_item_t *rcp, *rlcp;
    rcp = itemp->ai_right;
    rlcp = rcp->ai_left;
    if (itemp->ai_up) {
        if (itemp == itemp->ai_up->ai_right) {
            itemp->ai_up->ai_right = rlcp;
        } else {
            assert(itemp == itemp->ai_up->ai_left);
            itemp->ai_up->ai_left = rlcp;
        }
    } else {
        rootp->ar_root = rlcp;
    }
    rlcp->ai_up = itemp->ai_up;
    rcp->ai_left = rlcp->ai_right;
    if (rcp->ai_left)
        rcp->ai_left->ai_up = rcp;
    itemp->ai_right = rlcp->ai_left;
    if (itemp->ai_right)
        itemp->ai_right->ai_up = itemp;
    rlcp->ai_right = rcp;
    rlcp->ai_left = itemp;
    rcp->ai_up = rlcp;
    itemp->ai_up = rlcp;
}

static void
avl_delete_fix(avl_root_t *rootp, avl_item_t *itemp, avl_item_t *parentp)
{
    avl_item_t *childp;

    if ((parentp->ai_left == NULL) &&
        (parentp->ai_right == NULL)) {
        assert(itemp == NULL);
        parentp->ai_balance = CENT;
        itemp = parentp;
        parentp = itemp->ai_up;
    }

    while (parentp) {
        if (itemp == parentp->ai_right) {
            itemp = parentp->ai_left;
            if (parentp->ai_balance == LEFT) {
                /* Parent was left-heavy, now worse */
                if (itemp->ai_balance == LEFT) {
                    /* If left child is also
                     * left-heavy, LL fixes it. */
                    _avl_rotate_ll(rootp, parentp);
                    itemp->ai_balance = CENT;
                    parentp->ai_balance = CENT;
                    parentp = itemp;
                } else if (itemp->ai_balance == CENT) {
                    _avl_rotate_ll(rootp, parentp);
                    itemp->ai_balance = RIGHT;
                    parentp->ai_balance = LEFT;
                    break;
                } else {
                    childp = itemp->ai_right;
                    _avl_rotate_lr(rootp, parentp);
                    itemp->ai_balance = CENT;
                    parentp->ai_balance = CENT;
                    if (childp->ai_balance == RIGHT)
                        itemp->ai_balance = LEFT;
                    if (childp->ai_balance == LEFT)
                        parentp->ai_balance = RIGHT;
                    childp->ai_balance = CENT;
                    parentp = childp;
                }
            } else if (parentp->ai_balance == CENT) {
                parentp->ai_balance = LEFT;
                break;
            } else {
                parentp->ai_balance = CENT;
            }

        } else {
            itemp = parentp->ai_right;
            if (parentp->ai_balance == RIGHT) {
                if (itemp->ai_balance == RIGHT) {
                    _avl_rotate_rr(rootp, parentp);
                    itemp->ai_balance = CENT;
                    parentp->ai_balance = CENT;
                    parentp = itemp;
                } else if (itemp->ai_balance == CENT) {
                    _avl_rotate_rr(rootp, parentp);
                    itemp->ai_balance = LEFT;
                    parentp->ai_balance = RIGHT;
                    break;
                } else {
                    childp = itemp->ai_left;
                    _avl_rotate_rl(rootp, parentp);

                    itemp->ai_balance = CENT;
                    parentp->ai_balance = CENT;
                    if (childp->ai_balance == RIGHT)
                        parentp->ai_balance = LEFT;
                    if (childp->ai_balance == LEFT)
                        itemp->ai_balance = RIGHT;
                    childp->ai_balance = CENT;
                    parentp = childp;
                }
            } else if (parentp->ai_balance == CENT) {
                parentp->ai_balance = RIGHT;
                break;
            } else {
                parentp->ai_balance = CENT;
            }
        }

        itemp = parentp;
        parentp = itemp->ai_up;
    }
}

static void
avl_insert_fix(avl_root_t *rootp, avl_item_t *itemp)
{
    avl_item_t *childp, *parentp = itemp->ai_up;
    itemp->ai_left = itemp->ai_right = NULL;
#ifndef NDEBUG
    assert(!itemp->ai_indexed);
    itemp->ai_indexed = 1;
#endif
    while (parentp) {
        if (itemp == parentp->ai_left) {
            if (parentp->ai_balance == LEFT) {
                /* Parent was left-heavy, now worse */
                if (itemp->ai_balance == LEFT) {
                    /* If left child is also
                     * left-heavy, LL fixes it. */
                    _avl_rotate_ll(rootp, parentp);
                    itemp->ai_balance = CENT;
                    parentp->ai_balance = CENT;
                    break;
                } else {
                    assert(itemp->ai_balance != CENT);
                    childp = itemp->ai_right;
                    _avl_rotate_lr(rootp, parentp);
                    itemp->ai_balance = CENT;
                    parentp->ai_balance = CENT;
                    if (childp->ai_balance == RIGHT)
                        itemp->ai_balance = LEFT;
                    if (childp->ai_balance == LEFT)
                        parentp->ai_balance = RIGHT;
                    childp->ai_balance = CENT;
                    break;
                }
            } else if (parentp->ai_balance == CENT) {
                parentp->ai_balance = LEFT;
            } else {
                parentp->ai_balance = CENT;
                return;
            }
        } else {
            if (parentp->ai_balance == RIGHT) {
                if (itemp->ai_balance == RIGHT) {
                    _avl_rotate_rr(rootp, parentp);
                    itemp->ai_balance = CENT;
                    parentp->ai_balance = CENT;
                    break;
                } else {
                    assert(itemp->ai_balance != CENT);
                    childp = itemp->ai_left;
                    _avl_rotate_rl(rootp, parentp);
                    itemp->ai_balance = CENT;
                    parentp->ai_balance = CENT;
                    if (childp->ai_balance == RIGHT)
                        parentp->ai_balance = LEFT;
                    if (childp->ai_balance == LEFT)
                        itemp->ai_balance = RIGHT;
                    childp->ai_balance = CENT;
                    break;
                }
            } else if (parentp->ai_balance == CENT) {
                parentp->ai_balance = RIGHT;
            } else {
                parentp->ai_balance = CENT;
                break;
            }
        }

        itemp = parentp;
        parentp = itemp->ai_up;
    }
}

static INLINE avl_item_t *
avl_first(avl_root_t *rootp)
{
    avl_item_t *itemp = rootp->ar_root;
    if (itemp) {
        while (itemp->ai_left)
            itemp = itemp->ai_left;
    }
    return itemp;
}

static INLINE avl_item_t *
avl_next(avl_item_t *itemp)
{
    if (itemp->ai_right) {
        itemp = itemp->ai_right;
        while (itemp->ai_left)
            itemp = itemp->ai_left;
        return itemp;
    }

    while (itemp->ai_up && (itemp == itemp->ai_up->ai_right))
        itemp = itemp->ai_up;

    if (!itemp->ai_up)
        return NULL;

    return itemp->ai_up;
}

static void
avl_remove(avl_root_t *rootp, avl_item_t *itemp)
{
    avl_item_t *relocp, *replacep, *parentp = NULL;
#ifndef NDEBUG
    assert(itemp->ai_indexed);
    itemp->ai_indexed = 0;
#endif
    /* If the item is directly replaceable, do it. */
    if ((itemp->ai_left == NULL) || (itemp->ai_right == NULL)) {
        parentp = itemp->ai_up;
        replacep = itemp->ai_left;
        if (replacep == NULL)
            replacep = itemp->ai_right;
        if (replacep != NULL)
            replacep->ai_up = parentp;
        if (parentp == NULL) {
            rootp->ar_root = replacep;
        } else {
            if (itemp == parentp->ai_left)
                parentp->ai_left = replacep;
            else
                parentp->ai_right = replacep;

            avl_delete_fix(rootp, replacep, parentp);
        }
        return;
    }

    /*
     * Otherwise we do an indirect replacement with
     * the item's leftmost right descendant.
     */
    relocp = avl_next(itemp);
    assert(relocp);
    assert(relocp->ai_up != NULL);
    assert(relocp->ai_left == NULL);
    replacep = relocp->ai_right;
    relocp->ai_left = itemp->ai_left;
    if (relocp->ai_left != NULL)
        relocp->ai_left->ai_up = relocp;
    if (itemp->ai_up == NULL)
        rootp->ar_root = relocp;
    else {
        if (itemp == itemp->ai_up->ai_left)
            itemp->ai_up->ai_left = relocp;
        else
            itemp->ai_up->ai_right = relocp;
    }
    if (relocp == relocp->ai_up->ai_left) {
        assert(relocp->ai_up != itemp);
        relocp->ai_up->ai_left = replacep;
        parentp = relocp->ai_up;
        if (replacep != NULL)
            replacep->ai_up = relocp->ai_up;
        relocp->ai_right = itemp->ai_right;
    } else {
        assert(relocp->ai_up == itemp);
        relocp->ai_right = replacep;
        parentp = relocp;
    }
    if (relocp->ai_right != NULL)
        relocp->ai_right->ai_up = relocp;
    relocp->ai_up = itemp->ai_up;
    relocp->ai_balance = itemp->ai_balance;
    avl_delete_fix(rootp, replacep, parentp);
}

#endif
