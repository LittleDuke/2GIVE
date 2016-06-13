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

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <math.h>
#include <assert.h>

#include <pthread.h>

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/obj_mac.h>

// util.c

#if defined(WIN32)
#define _USE_MATH_DEFINES
#endif /* defined(WIN32) */


#include "vanitygen.h"

// pattern.c

#include <pcre.h>

const char *version = VANITYGEN_VERSION;
char VG_PUB_KEY_BUF[64];
char VG_PRV_KEY_BUF[VG_PROTKEY_MAX_B58];


// winglue.c

#if defined(WIN32)

#include <windows.h>
#include <stdio.h>
#include <pthread.h>

int
count_processors(void)
{
    typedef BOOL (WINAPI *LPFN_GLPI)(
        PSYSTEM_LOGICAL_PROCESSOR_INFORMATION, PDWORD);
    LPFN_GLPI glpi;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buffer = NULL, ptr;
    DWORD size = 0, count = 0, pos = 0, i, ret;

    glpi = (LPFN_GLPI) GetProcAddress(GetModuleHandle(TEXT("kernel32")),
                      "GetLogicalProcessorInformation");
    if (!glpi)
        return -1;

    while (1) {
        ret = glpi(buffer, &size);
        if (ret)
            break;
        if (buffer)
            free(buffer);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            return -1;
        buffer = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION) malloc(size);
        if (!buffer)
            return -1;
    }

    for (ptr = buffer;
         (pos + sizeof(*ptr)) <= size;
         ptr++, pos += sizeof(*ptr)) {
        switch (ptr->Relationship) {
        case RelationProcessorCore:
            for (i = ptr->ProcessorMask; i != 0; i >>= 1) {
                if (i & 1)
                    count++;
            }
            break;
        default:
            break;
        }
    }

    if (buffer)
        free(buffer);
    return count;
}


/*
 * struct timeval compatibility for Win32
 */

#define TIMESPEC_TO_FILETIME_OFFSET \
      ( ((unsigned __int64) 27111902 << 32) + \
        (unsigned __int64) 3577643008 )

int
gettimeofday(struct timeval *tv, struct timezone *tz)
{
    FILETIME ft;
    unsigned __int64 tmpres = 0;

    if (NULL != tv) {
        GetSystemTimeAsFileTime(&ft);

        tv->tv_sec = (int) ((*(unsigned __int64 *) &ft -
                     TIMESPEC_TO_FILETIME_OFFSET) /
                    10000000);
        tv->tv_usec = (int) ((*(unsigned __int64 *) &ft -
                      TIMESPEC_TO_FILETIME_OFFSET -
                      ((unsigned __int64) tv->tv_sec *
                       (unsigned __int64) 10000000)) / 10);
    }

    return 0;
}

void
timeradd(struct timeval *a, struct timeval *b, struct timeval *result)
{
    result->tv_sec = a->tv_sec + b->tv_sec;
    result->tv_usec = a->tv_usec + b->tv_usec;
    if (result->tv_usec > 10000000) {
        result->tv_sec++;
        result->tv_usec -= 1000000;
    }
}

void
timersub(struct timeval *a, struct timeval *b, struct timeval *result)
{
    result->tv_sec = a->tv_sec - b->tv_sec;
    result->tv_usec = a->tv_usec - b->tv_usec;
    if (result->tv_usec < 0) {
        result->tv_sec--;
        result->tv_usec += 1000000;
    }
}

/*
 * getopt() for Win32 -- public domain ripped from codeproject.com
 */
/*
TCHAR *optarg = NULL;
int optind = 0;

int getopt(int argc, TCHAR *argv[], TCHAR *optstring)
{
    static TCHAR *next = NULL;
    TCHAR c;
    TCHAR *cp;

    if (optind == 0)
        next = NULL;

    optarg = NULL;

    if (next == NULL || *next == _T('\0'))
    {
        if (optind == 0)
            optind++;

        if (optind >= argc || argv[optind][0] != _T('-') || argv[optind][1] == _T('\0'))
        {
            optarg = NULL;
            if (optind < argc)
                optarg = argv[optind];
            return EOF;
        }

        if (_tcscmp(argv[optind], _T("--")) == 0)
        {
            optind++;
            optarg = NULL;
            if (optind < argc)
                optarg = argv[optind];
            return EOF;
        }

        next = argv[optind];
        next++;		// skip past -
        optind++;
    }

    c = *next++;
    cp = _tcschr(optstring, c);

    if (cp == NULL || c == _T(':'))
        return _T('?');

    cp++;
    if (*cp == _T(':'))
    {
        if (*next != _T('\0'))
        {
            optarg = next;
            next = NULL;
        }
        else if (optind < argc)
        {
            optarg = argv[optind];
            optind++;
        }
        else
        {
            return _T('?');
        }
    }

    return c;
}
*/
/*
 * If ptw32 is being linked in as a static library, make sure that
 * its process attach function gets called before main().
 */
#if defined(PTW32_STATIC_LIB)

int __cdecl __initptw32(void);

#if defined(_MSC_VER)
class __constructme { public: __constructme() { __initptw32(); } } __vg_pinit;
#define CONSTRUCTOR_TYPE __cdecl
#elif defined(__GNUC__)
#define CONSTRUCTOR_TYPE __cdecl __attribute__((constructor))
#else
#error "Unknown compiler -- can't mark constructor"
#endif

int CONSTRUCTOR_TYPE
__initptw32(void)
{
    pthread_win32_process_attach_np();
    return 0;
}
#endif // defined(WIN32)

#endif // defined(WIN32)



// util.c

const char *vg_b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const signed char vg_b58_reverse_map[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
    -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
    -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
    47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};


void
fdumphex(FILE *fp, const unsigned char *src, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        fprintf(fp, "%02x", src[i]);
    }
    printf("\n");
}

void
fdumpbn(FILE *fp, const BIGNUM *bn)
{
    char *buf;
    buf = BN_bn2hex(bn);
    fprintf(fp, "%s\n", buf ? buf : "0");
    if (buf)
        OPENSSL_free(buf);
}

void
dumphex(const unsigned char *src, size_t len)
{
    fdumphex(stdout, src, len);
}

void
dumpbn(const BIGNUM *bn)
{
    fdumpbn(stdout, bn);
}

/*
 * Key format encode/decode
 */

void
vg_b58_encode_check(void *buf, size_t len, char *result)
{
    unsigned char hash1[32];
    unsigned char hash2[32];

    int d, p;

    BN_CTX *bnctx;
    BIGNUM *bn, *bndiv, *bntmp;
    BIGNUM bna, bnb, bnbase, bnrem;
    unsigned char *binres;
    int brlen, zpfx;

    bnctx = BN_CTX_new();
    BN_init(&bna);
    BN_init(&bnb);
    BN_init(&bnbase);
    BN_init(&bnrem);
    BN_set_word(&bnbase, 58);

    bn = &bna;
    bndiv = &bnb;

    brlen = (2 * len) + 4;
    binres = (unsigned char*) malloc(brlen);
    memcpy(binres, buf, len);

    SHA256(binres, len, hash1);
    SHA256(hash1, sizeof(hash1), hash2);
    memcpy(&binres[len], hash2, 4);

    BN_bin2bn(binres, len + 4, bn);

    for (zpfx = 0; zpfx < (len + 4) && binres[zpfx] == 0; zpfx++) ;

    p = brlen;
    while (!BN_is_zero(bn)) {
        BN_div(bndiv, &bnrem, bn, &bnbase, bnctx);
        bntmp = bn;
        bn = bndiv;
        bndiv = bntmp;
        d = BN_get_word(&bnrem);
        binres[--p] = vg_b58_alphabet[d];
    }

    while (zpfx--) {
        binres[--p] = vg_b58_alphabet[0];
    }

    memcpy(result, &binres[p], brlen - p);
    result[brlen - p] = '\0';

    free(binres);
    BN_clear_free(&bna);
    BN_clear_free(&bnb);
    BN_clear_free(&bnbase);
    BN_clear_free(&bnrem);
    BN_CTX_free(bnctx);
}

#define skip_char(c) \
    (((c) == '\r') || ((c) == '\n') || ((c) == ' ') || ((c) == '\t'))

int
vg_b58_decode_check(const char *input, void *buf, size_t len)
{
    int i, l, c;
    unsigned char *xbuf = NULL;
    BIGNUM bn, bnw, bnbase;
    BN_CTX *bnctx;
    unsigned char hash1[32], hash2[32];
    int zpfx;
    int res = 0;

    BN_init(&bn);
    BN_init(&bnw);
    BN_init(&bnbase);
    BN_set_word(&bnbase, 58);
    bnctx = BN_CTX_new();

    /* Build a bignum from the encoded value */
    l = strlen(input);
    for (i = 0; i < l; i++) {
        if (skip_char(input[i]))
            continue;
        c = vg_b58_reverse_map[(int)input[i]];
        if (c < 0)
            goto out;
        BN_clear(&bnw);
        BN_set_word(&bnw, c);
        BN_mul(&bn, &bn, &bnbase, bnctx);
        BN_add(&bn, &bn, &bnw);
    }

    /* Copy the bignum to a byte buffer */
    for (i = 0, zpfx = 0; input[i]; i++) {
        if (skip_char(input[i]))
            continue;
        if (input[i] != vg_b58_alphabet[0])
            break;
        zpfx++;
    }
    c = BN_num_bytes(&bn);
    l = zpfx + c;
    if (l < 5)
        goto out;
    xbuf = (unsigned char *) malloc(l);
    if (!xbuf)
        goto out;
    if (zpfx)
        memset(xbuf, 0, zpfx);
    if (c)
        BN_bn2bin(&bn, xbuf + zpfx);

    /* Check the hash code */
    l -= 4;
    SHA256(xbuf, l, hash1);
    SHA256(hash1, sizeof(hash1), hash2);
    if (memcmp(hash2, xbuf + l, 4))
        goto out;

    /* Buffer verified */
    if (len) {
        if (len > l)
            len = l;
        memcpy(buf, xbuf, len);
    }
    res = l;

out:
    if (xbuf)
        free(xbuf);
    BN_clear_free(&bn);
    BN_clear_free(&bnw);
    BN_clear_free(&bnbase);
    BN_CTX_free(bnctx);
    return res;
}

void
vg_encode_address(const EC_POINT *ppoint, const EC_GROUP *pgroup,
          int addrtype, char *result)
{
    unsigned char eckey_buf[128], *pend;
    unsigned char binres[21] = {0,};
    unsigned char hash1[32];

    pend = eckey_buf;

    EC_POINT_point2oct(pgroup,
               ppoint,
               POINT_CONVERSION_UNCOMPRESSED,
               eckey_buf,
               sizeof(eckey_buf),
               NULL);
    pend = eckey_buf + 0x41;
    binres[0] = addrtype;
    SHA256(eckey_buf, pend - eckey_buf, hash1);
    RIPEMD160(hash1, sizeof(hash1), &binres[1]);

    vg_b58_encode_check(binres, sizeof(binres), result);
}

void
vg_encode_script_address(const EC_POINT *ppoint, const EC_GROUP *pgroup,
             int addrtype, char *result)
{
    unsigned char script_buf[69];
    unsigned char *eckey_buf = script_buf + 2;
    unsigned char binres[21] = {0,};
    unsigned char hash1[32];

    script_buf[ 0] = 0x51;  // OP_1
    script_buf[ 1] = 0x41;  // pubkey length
    // gap for pubkey
    script_buf[67] = 0x51;  // OP_1
    script_buf[68] = 0xae;  // OP_CHECKMULTISIG

    EC_POINT_point2oct(pgroup,
               ppoint,
               POINT_CONVERSION_UNCOMPRESSED,
               eckey_buf,
               65,
               NULL);
    binres[0] = addrtype;
    SHA256(script_buf, 69, hash1);
    RIPEMD160(hash1, sizeof(hash1), &binres[1]);

    vg_b58_encode_check(binres, sizeof(binres), result);
}

void
vg_encode_privkey(const EC_KEY *pkey, int addrtype, char *result)
{
    unsigned char eckey_buf[128];
    const BIGNUM *bn;
    int nbytes;

    bn = EC_KEY_get0_private_key(pkey);

    eckey_buf[0] = addrtype;
    nbytes = BN_num_bytes(bn);
    assert(nbytes <= 32);
    if (nbytes < 32)
        memset(eckey_buf + 1, 0, 32 - nbytes);
    BN_bn2bin(bn, &eckey_buf[33 - nbytes]);

    vg_b58_encode_check(eckey_buf, 33, result);
}

int
vg_set_privkey(const BIGNUM *bnpriv, EC_KEY *pkey)
{
    const EC_GROUP *pgroup;
    EC_POINT *ppnt;
    int res;

    pgroup = EC_KEY_get0_group(pkey);
    ppnt = EC_POINT_new(pgroup);

    res = (ppnt &&
           EC_KEY_set_private_key(pkey, bnpriv) &&
           EC_POINT_mul(pgroup, ppnt, bnpriv, NULL, NULL, NULL) &&
           EC_KEY_set_public_key(pkey, ppnt));

    if (ppnt)
        EC_POINT_free(ppnt);

    if (!res)
        return 0;

    assert(EC_KEY_check_key(pkey));
    return 1;
}

int
vg_decode_privkey(const char *b58encoded, EC_KEY *pkey, int *addrtype)
{
    BIGNUM bnpriv;
    unsigned char ecpriv[48];
    int res;

    res = vg_b58_decode_check(b58encoded, ecpriv, sizeof(ecpriv));
    if (res != 33)
        return 0;

    BN_init(&bnpriv);
    BN_bin2bn(ecpriv + 1, res - 1, &bnpriv);
    res = vg_set_privkey(&bnpriv, pkey);
    BN_clear_free(&bnpriv);
    *addrtype = ecpriv[0];
    return 1;
}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
/* The generic PBKDF2 function first appeared in OpenSSL 1.0 */
/* ====================================================================
 * Copyright (c) 1999-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
int
PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
          const unsigned char *salt, int saltlen, int iter,
          const EVP_MD *digest,
          int keylen, unsigned char *out)
{
    unsigned char digtmp[EVP_MAX_MD_SIZE], *p, itmp[4];
    int cplen, j, k, tkeylen, mdlen;
    unsigned long i = 1;
    HMAC_CTX hctx;

    mdlen = EVP_MD_size(digest);
    if (mdlen < 0)
        return 0;

    HMAC_CTX_init(&hctx);
    p = out;
    tkeylen = keylen;
    if(!pass)
        passlen = 0;
    else if(passlen == -1)
        passlen = strlen(pass);
    while(tkeylen)
        {
        if(tkeylen > mdlen)
            cplen = mdlen;
        else
            cplen = tkeylen;
        /* We are unlikely to ever use more than 256 blocks (5120 bits!)
         * but just in case...
         */
        itmp[0] = (unsigned char)((i >> 24) & 0xff);
        itmp[1] = (unsigned char)((i >> 16) & 0xff);
        itmp[2] = (unsigned char)((i >> 8) & 0xff);
        itmp[3] = (unsigned char)(i & 0xff);
        HMAC_Init_ex(&hctx, pass, passlen, digest, NULL);
        HMAC_Update(&hctx, salt, saltlen);
        HMAC_Update(&hctx, itmp, 4);
        HMAC_Final(&hctx, digtmp, NULL);
        memcpy(p, digtmp, cplen);
        for(j = 1; j < iter; j++)
            {
            HMAC(digest, pass, passlen,
                 digtmp, mdlen, digtmp, NULL);
            for(k = 0; k < cplen; k++)
                p[k] ^= digtmp[k];
            }
        tkeylen-= cplen;
        i++;
        p+= cplen;
        }
    HMAC_CTX_cleanup(&hctx);
    return 1;
}
#endif  /* OPENSSL_VERSION_NUMBER < 0x10000000L */


typedef struct {
    int mode;
    int iterations;
    const EVP_MD *(*pbkdf_hash_getter)(void);
    const EVP_CIPHER *(*cipher_getter)(void);
} vg_protkey_parameters_t;

static const vg_protkey_parameters_t protkey_parameters[] = {
    { 0, 4096,  EVP_sha256, EVP_aes_256_cbc },
    { 0, 0, NULL, NULL },
    { 0, 0, NULL, NULL },
    { 0, 0, NULL, NULL },
    { 0, 0, NULL, NULL },
    { 0, 0, NULL, NULL },
    { 0, 0, NULL, NULL },
    { 0, 0, NULL, NULL },
    { 0, 0, NULL, NULL },
    { 0, 0, NULL, NULL },
    { 0, 0, NULL, NULL },
    { 0, 0, NULL, NULL },
    { 0, 0, NULL, NULL },
    { 0, 0, NULL, NULL },
    { 0, 0, NULL, NULL },
    { 0, 0, NULL, NULL },
    { 1, 4096,  EVP_sha256, EVP_aes_256_cbc },
};

static int
vg_protect_crypt(int parameter_group,
         unsigned char *data_in, int data_in_len,
         unsigned char *data_out,
         const char *pass, int enc)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *salt;
    unsigned char keymaterial[EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH +
                  EVP_MAX_MD_SIZE];
    unsigned char hmac[EVP_MAX_MD_SIZE];
    int hmac_len = 0, hmac_keylen = 0;
    int salt_len;
    int plaintext_len = 32;
    int ciphertext_len;
    int pkcs7_padding = 1;
    const vg_protkey_parameters_t *params;
    const EVP_CIPHER *cipher;
    const EVP_MD *pbkdf_digest;
    const EVP_MD *hmac_digest;
    unsigned int hlen;
    int opos, olen, oincr, nbytes;
    int ipos;
    int ret = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto out;

    if (parameter_group < 0) {
        if (enc)
            parameter_group = 0;
        else
            parameter_group = data_in[0];
    } else {
        if (!enc && (parameter_group != data_in[0]))
            goto out;
    }

    if (parameter_group > (sizeof(protkey_parameters) /
                   sizeof(protkey_parameters[0])))
        goto out;
    params = &protkey_parameters[parameter_group];

    if (!params->iterations || !params->pbkdf_hash_getter)
        goto out;

    pbkdf_digest = params->pbkdf_hash_getter();
    cipher = params->cipher_getter();

    if (params->mode == 0) {
        /* Brief encoding */
        salt_len = 4;
        hmac_len = 8;
        hmac_keylen = 16;
        ciphertext_len = ((plaintext_len + cipher->block_size - 1) /
                  cipher->block_size) * cipher->block_size;
        pkcs7_padding = 0;
        hmac_digest = EVP_sha256();
    } else {
        /* PKCS-compliant encoding */
        salt_len = 8;
        ciphertext_len = ((plaintext_len + cipher->block_size) /
                  cipher->block_size) * cipher->block_size;
        hmac_digest = NULL;
    }

    if (!enc && (data_in_len != (1 + ciphertext_len + hmac_len + salt_len)))
        goto out;

    if (!pass || !data_out) {
        /* Format check mode */
        ret = plaintext_len;
        goto out;
    }

    if (!enc) {
        salt = data_in + 1 + ciphertext_len + hmac_len;
    } else if (salt_len) {
        salt = data_out + 1 + ciphertext_len + hmac_len;
        RAND_bytes(salt, salt_len);
    } else {
        salt = NULL;
    }

    PKCS5_PBKDF2_HMAC((const char *) pass, strlen(pass) + 1,
              salt, salt_len,
              params->iterations,
              pbkdf_digest,
              cipher->key_len + cipher->iv_len + hmac_keylen,
              keymaterial);

    if (!EVP_CipherInit(ctx, cipher,
                keymaterial,
                keymaterial + cipher->key_len,
                enc)) {
        fprintf(stderr, "ERROR: could not configure cipher\n");
        goto out;
    }

    if (!pkcs7_padding)
        EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (!enc) {
        opos = 0;
        olen = plaintext_len;
        nbytes = ciphertext_len;
        ipos = 1;
    } else {
        data_out[0] = parameter_group;
        opos = 1;
        olen = 1 + ciphertext_len + hmac_len + salt_len - opos;
        nbytes = plaintext_len;
        ipos = 0;
    }

    oincr = olen;
    if (!EVP_CipherUpdate(ctx, data_out + opos, &oincr,
                  data_in + ipos, nbytes))
        goto invalid_pass;
    opos += oincr;
    olen -= oincr;
    oincr = olen;
    if (!EVP_CipherFinal(ctx, data_out + opos, &oincr))
        goto invalid_pass;
    opos += oincr;

    if (hmac_len) {
        hlen = sizeof(hmac);
        HMAC(hmac_digest,
             keymaterial + cipher->key_len + cipher->iv_len,
             hmac_keylen,
             enc ? data_in : data_out, plaintext_len,
             hmac, &hlen);
        if (enc) {
            memcpy(data_out + 1 + ciphertext_len, hmac, hmac_len);
        } else if (memcmp(hmac,
                  data_in + 1 + ciphertext_len,
                  hmac_len))
            goto invalid_pass;
    }

    if (enc) {
        if (opos != (1 + ciphertext_len)) {
            fprintf(stderr, "ERROR: plaintext size mismatch\n");
            goto out;
        }
        opos += hmac_len + salt_len;
    } else if (opos != plaintext_len) {
        fprintf(stderr, "ERROR: plaintext size mismatch\n");
        goto out;
    }

    ret = opos;

    if (0) {
    invalid_pass:
        fprintf(stderr, "ERROR: Invalid password\n");
    }

out:
    OPENSSL_cleanse(hmac, sizeof(hmac));
    OPENSSL_cleanse(keymaterial, sizeof(keymaterial));
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int
vg_protect_encode_privkey(char *out,
              const EC_KEY *pkey, int keytype,
              int parameter_group,
              const char *pass)
{
    unsigned char ecpriv[64];
    unsigned char ecenc[128];
    const BIGNUM *privkey;
    int nbytes;
    int restype;

    restype = (keytype & 1) ? 79 : 32;

    privkey = EC_KEY_get0_private_key(pkey);
    nbytes = BN_num_bytes(privkey);
    if (nbytes < 32)
        memset(ecpriv, 0, 32 - nbytes);
    BN_bn2bin(privkey, ecpriv + 32 - nbytes);

    nbytes = vg_protect_crypt(parameter_group,
                  ecpriv, 32,
                  &ecenc[1], pass, 1);
    if (nbytes <= 0)
        return 0;

    OPENSSL_cleanse(ecpriv, sizeof(ecpriv));

    ecenc[0] = restype;
    vg_b58_encode_check(ecenc, nbytes + 1, out);
    nbytes = strlen(out);
    return nbytes;
}


int
vg_protect_decode_privkey(EC_KEY *pkey, int *keytype,
              const char *encoded, const char *pass)
{
    unsigned char ecpriv[64];
    unsigned char ecenc[128];
    BIGNUM bn;
    int restype;
    int res;

    res = vg_b58_decode_check(encoded, ecenc, sizeof(ecenc));

    if ((res < 2) || (res > sizeof(ecenc)))
        return 0;

    switch (ecenc[0]) {
    case 32:  restype = 128; break;
    case 79:  restype = 239; break;
    default:
        return 0;
    }

    if (!vg_protect_crypt(-1,
                  ecenc + 1, res - 1,
                  pkey ? ecpriv : NULL,
                  pass, 0))
        return 0;

    res = 1;
    if (pkey) {
        BN_init(&bn);
        BN_bin2bn(ecpriv, 32, &bn);
        res = vg_set_privkey(&bn, pkey);
        BN_clear_free(&bn);
        OPENSSL_cleanse(ecpriv, sizeof(ecpriv));
    }

    *keytype = restype;
    return res;
}

/*
 * Besides the bitcoin-adapted formats, we also support PKCS#8.
 */
int
vg_pkcs8_encode_privkey(char *out, int outlen,
            const EC_KEY *pkey, const char *pass)
{
    EC_KEY *pkey_copy = NULL;
    EVP_PKEY *evp_key = NULL;
    PKCS8_PRIV_KEY_INFO *pkcs8 = NULL;
    X509_SIG *pkcs8_enc = NULL;
    BUF_MEM *memptr;
    BIO *bio = NULL;
    int res = 0;

    pkey_copy = EC_KEY_dup(pkey);
    if (!pkey_copy)
        goto out;
    evp_key = EVP_PKEY_new();
    if (!evp_key || !EVP_PKEY_set1_EC_KEY(evp_key, pkey_copy))
        goto out;
    pkcs8 = EVP_PKEY2PKCS8(evp_key);
    if (!pkcs8)
        goto out;

    bio = BIO_new(BIO_s_mem());
    if (!bio)
        goto out;

    if (!pass) {
        res = PEM_write_bio_PKCS8_PRIV_KEY_INFO(bio, pkcs8);

    } else {
        pkcs8_enc = PKCS8_encrypt(-1,
                      EVP_aes_256_cbc(),
                      pass, strlen(pass),
                      NULL, 0,
                      4096,
                      pkcs8);
        if (!pkcs8_enc)
            goto out;
        res = PEM_write_bio_PKCS8(bio, pkcs8_enc);
    }

    BIO_get_mem_ptr(bio, &memptr);
    res = memptr->length;
    if (res < outlen) {
        memcpy(out, memptr->data, res);
        out[res] = '\0';
    } else {
        memcpy(out, memptr->data, outlen - 1);
        out[outlen-1] = '\0';
    }

out:
    if (bio)
        BIO_free(bio);
    if (pkey_copy)
        EC_KEY_free(pkey_copy);
    if (evp_key)
        EVP_PKEY_free(evp_key);
    if (pkcs8)
        PKCS8_PRIV_KEY_INFO_free(pkcs8);
    if (pkcs8_enc)
        X509_SIG_free(pkcs8_enc);
    return res;
}

int
vg_pkcs8_decode_privkey(EC_KEY *pkey, const char *pem_in, const char *pass)
{
    EC_KEY *pkey_in = NULL;
    EC_KEY *test_key = NULL;
    EVP_PKEY *evp_key = NULL;
    PKCS8_PRIV_KEY_INFO *pkcs8 = NULL;
    X509_SIG *pkcs8_enc = NULL;
    BIO *bio = NULL;
    int res = 0;

    bio = BIO_new_mem_buf((char *)pem_in, strlen(pem_in));
    if (!bio)
        goto out;

    pkcs8_enc = PEM_read_bio_PKCS8(bio, NULL, NULL, NULL);
    if (pkcs8_enc) {
        if (!pass)
            return -1;
        pkcs8 = PKCS8_decrypt(pkcs8_enc, pass, strlen(pass));

    } else {
        (void) BIO_reset(bio);
        pkcs8 = PEM_read_bio_PKCS8_PRIV_KEY_INFO(bio, NULL, NULL, NULL);
    }

    if (!pkcs8)
        goto out;
    evp_key = EVP_PKCS82PKEY(pkcs8);
    if (!evp_key)
        goto out;
    pkey_in = EVP_PKEY_get1_EC_KEY(evp_key);
    if (!pkey_in)
        goto out;

    /* Expect a specific curve */
    test_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!test_key ||
        EC_GROUP_cmp(EC_KEY_get0_group(pkey_in),
             EC_KEY_get0_group(test_key),
             NULL))
        goto out;

    if (!EC_KEY_copy(pkey, pkey_in))
        goto out;

    res = 1;

out:
    if (bio)
        BIO_free(bio);
    if (test_key)
        EC_KEY_free(pkey_in);
    if (evp_key)
        EVP_PKEY_free(evp_key);
    if (pkcs8)
        PKCS8_PRIV_KEY_INFO_free(pkcs8);
    if (pkcs8_enc)
        X509_SIG_free(pkcs8_enc);
    return res;
}


int
vg_decode_privkey_any(EC_KEY *pkey, int *addrtype, const char *input,
              const char *pass)
{
    int res;

    if (vg_decode_privkey(input, pkey, addrtype))
        return 1;
    if (vg_protect_decode_privkey(pkey, addrtype, input, NULL)) {
        if (!pass)
            return -1;
        return vg_protect_decode_privkey(pkey, addrtype, input, pass);
    }
    res = vg_pkcs8_decode_privkey(pkey, input, pass);
    if (res > 0) {
        /* Assume main network address */
        *addrtype = 128;
    }
    return res;
}


int
vg_read_password(char *buf, size_t size)
{
    return !EVP_read_pw_string(buf, size, "Enter new password:", 1);
}


/*
 * Password complexity checker
 * Heavily inspired by, but a simplification of "How Secure Is My Password?",
 * http://howsecureismypassword.net/
 */
static unsigned char ascii_class[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    5, 4, 5, 4, 4, 4, 4, 5, 4, 4, 4, 4, 5, 4, 5, 5,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 5, 5, 5, 4, 5, 5,
    4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 5, 5, 5, 4, 4,
    5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 5, 5, 5, 5, 0,
};

int
vg_check_password_complexity(const char *pass, int verbose)
{
    int i, len;
    int classes[6] = { 0, };
    const char *crackunit = "seconds";
    int char_complexity = 0;
    double crackops, cracktime;
    int weak;

    /*
     * This number reflects a resourceful attacker with
     * USD >$20K in 2011 hardware
     */
    const int rate = 250000000;

    /* Consider the password weak if it can be cracked in <1 year */
    const int weak_threshold = (60*60*24*365);

    len = strlen(pass);
    for (i = 0; i < len; i++) {
        if (pass[i] > sizeof(ascii_class))
            /* FIXME: skip the rest of the UTF8 char */
            classes[5]++;
        else if (!ascii_class[(int)pass[i]])
            continue;
        else
            classes[(int)ascii_class[(int)pass[i]] - 1]++;
    }

    if (classes[0])
        char_complexity += 26;
    if (classes[1])
        char_complexity += 26;
    if (classes[2])
        char_complexity += 10;
    if (classes[3])
        char_complexity += 14;
    if (classes[4])
        char_complexity += 19;
    if (classes[5])
        char_complexity += 32;  /* oversimplified */

    /* This assumes brute-force and oversimplifies the problem */
    crackops = pow((double)char_complexity, (double)len);
    cracktime = (crackops * (1 - (1/M_E))) / rate;
    weak = (cracktime < weak_threshold);

    if (cracktime > 60.0) {
        cracktime /= 60.0;
        crackunit = "minutes";
        if (cracktime > 60.0) {
            cracktime /= 60.0;
            crackunit = "hours";
            if (cracktime > 24.0) {
                cracktime /= 24;
                crackunit = "days";
                if (cracktime > 365.0) {
                    cracktime /= 365.0;
                    crackunit = "years";
                }
            }
        }
    }

    /* Complain by default about weak passwords */
    if ((weak && (verbose > 0)) || (verbose > 1)) {
        if (cracktime < 1.0) {
            fprintf(stderr,
                "Estimated password crack time: >1 %s\n",
                   crackunit);
        } else if (cracktime < 1000000) {
            fprintf(stderr,
                "Estimated password crack time: %.1f %s\n",
                cracktime, crackunit);
        } else {
            fprintf(stderr,
                "Estimated password crack time: %e %s\n",
                cracktime, crackunit);
        }
        if (!classes[0] && !classes[1] && classes[2] &&
            !classes[3] && !classes[4] && !classes[5]) {
            fprintf(stderr,
                "WARNING: Password contains only numbers\n");
        }
        else if (!classes[2] && !classes[3] && !classes[4] &&
             !classes[5]) {
            if (!classes[0] || !classes[1]) {
                fprintf(stderr,
                    "WARNING: Password contains "
                    "only %scase letters\n",
                    classes[0] ? "lower" : "upper");
            } else {
                fprintf(stderr,
                    "WARNING: Password contains "
                    "only letters\n");
            }
        }
    }

    return !weak;
}


/*
 * Pattern file reader
 * Absolutely disgusting, unable to free the pattern list when it's done
 */

int
vg_read_file(FILE *fp, char ***result, int *rescount)
{
    int ret = 1;

    char **patterns;
    char *buf = NULL, *obuf, *pat;
    const int blksize = 16*1024;
    int nalloc = 16;
    int npatterns = 0;
    int count, pos;

    patterns = (char**) malloc(sizeof(char*) * nalloc);
    count = 0;
    pos = 0;

    while (1) {
        obuf = buf;
        buf = (char *) malloc(blksize);
        if (!buf) {
            ret = 0;
            break;
        }
        if (pos < count) {
            memcpy(buf, &obuf[pos], count - pos);
        }
        pos = count - pos;
        count = fread(&buf[pos], 1, blksize - pos, fp);
        if (count < 0) {
            fprintf(stderr,
                "Error reading file: %s\n", strerror(errno));
            ret = 0;
        }
        if (count <= 0)
            break;
        count += pos;
        pat = buf;

        while (pos < count) {
            if ((buf[pos] == '\r') || (buf[pos] == '\n')) {
                buf[pos] = '\0';
                if (pat) {
                    if (npatterns == nalloc) {
                        nalloc *= 2;
                        patterns = (char**)
                            realloc(patterns,
                                sizeof(char*) *
                                nalloc);
                    }
                    patterns[npatterns] = pat;
                    npatterns++;
                    pat = NULL;
                }
            }
            else if (!pat) {
                pat = &buf[pos];
            }
            pos++;
        }

        pos = pat ? (pat - buf) : count;
    }

    *result = patterns;
    *rescount = npatterns;

    return ret;
}


/*
 * Address search thread main loop
 */

void *
vg_thread_loop(void *arg)
{
	unsigned char hash_buf[128];
	unsigned char *eckey_buf;
	unsigned char hash1[32];

	int i, c, len, output_interval;
	int hash_len;

	const BN_ULONG rekey_max = 10000000;
	BN_ULONG npoints, rekey_at, nbatch;

	vg_context_t *vcp = (vg_context_t *) arg;
	EC_KEY *pkey = NULL;
	const EC_GROUP *pgroup;
	const EC_POINT *pgen;
	const int ptarraysize = 256;
	EC_POINT *ppnt[ptarraysize];
	EC_POINT *pbatchinc;

	vg_test_func_t test_func = vcp->vc_test;
	vg_exec_context_t ctx;
	vg_exec_context_t *vxcp;

	struct timeval tvstart;


	memset(&ctx, 0, sizeof(ctx));
	vxcp = &ctx;

	vg_exec_context_init(vcp, &ctx);

	pkey = vxcp->vxc_key;
	pgroup = EC_KEY_get0_group(pkey);
	pgen = EC_GROUP_get0_generator(pgroup);

	for (i = 0; i < ptarraysize; i++) {
		ppnt[i] = EC_POINT_new(pgroup);
		if (!ppnt[i]) {
			fprintf(stderr, "ERROR: out of memory?\n");
			exit(1);
		}
	}
	pbatchinc = EC_POINT_new(pgroup);
	if (!pbatchinc) {
		fprintf(stderr, "ERROR: out of memory?\n");
		exit(1);
	}

	BN_set_word(&vxcp->vxc_bntmp, ptarraysize);
	EC_POINT_mul(pgroup, pbatchinc, &vxcp->vxc_bntmp, NULL, NULL,
		     vxcp->vxc_bnctx);
	EC_POINT_make_affine(pgroup, pbatchinc, vxcp->vxc_bnctx);

	npoints = 0;
	rekey_at = 0;
	nbatch = 0;
	vxcp->vxc_key = pkey;
	vxcp->vxc_binres[0] = vcp->vc_addrtype;
	c = 0;
	output_interval = 1000;
	gettimeofday(&tvstart, NULL);

	if (vcp->vc_format == VCF_SCRIPT) {
		hash_buf[ 0] = 0x51;  // OP_1
		hash_buf[ 1] = 0x41;  // pubkey length
		// gap for pubkey
		hash_buf[67] = 0x51;  // OP_1
		hash_buf[68] = 0xae;  // OP_CHECKMULTISIG
		eckey_buf = hash_buf + 2;
		hash_len = 69;

	} else {
		eckey_buf = hash_buf;
		hash_len = 65;
	}

	while (!vcp->vc_halt) {
		if (++npoints >= rekey_at) {
			vg_exec_context_upgrade_lock(vxcp);
			/* Generate a new random private key */
			EC_KEY_generate_key(pkey);
			npoints = 0;

			/* Determine rekey interval */
			EC_GROUP_get_order(pgroup, &vxcp->vxc_bntmp,
					   vxcp->vxc_bnctx);
			BN_sub(&vxcp->vxc_bntmp2,
			       &vxcp->vxc_bntmp,
			       EC_KEY_get0_private_key(pkey));
			rekey_at = BN_get_word(&vxcp->vxc_bntmp2);
			if ((rekey_at == BN_MASK2) || (rekey_at > rekey_max))
				rekey_at = rekey_max;
			assert(rekey_at > 0);

			EC_POINT_copy(ppnt[0], EC_KEY_get0_public_key(pkey));
			vg_exec_context_downgrade_lock(vxcp);

			npoints++;
			vxcp->vxc_delta = 0;

			if (vcp->vc_pubkey_base)
				EC_POINT_add(pgroup,
					     ppnt[0],
					     ppnt[0],
					     vcp->vc_pubkey_base,
					     vxcp->vxc_bnctx);

			for (nbatch = 1;
			     (nbatch < ptarraysize) && (npoints < rekey_at);
			     nbatch++, npoints++) {
				EC_POINT_add(pgroup,
					     ppnt[nbatch],
					     ppnt[nbatch-1],
					     pgen, vxcp->vxc_bnctx);
			}

		} else {
			/*
			 * Common case
			 *
			 * EC_POINT_add() can skip a few multiplies if
			 * one or both inputs are affine (Z_is_one).
			 * This is the case for every point in ppnt, as
			 * well as pbatchinc.
			 */
			assert(nbatch == ptarraysize);
			for (nbatch = 0;
			     (nbatch < ptarraysize) && (npoints < rekey_at);
			     nbatch++, npoints++) {
				EC_POINT_add(pgroup,
					     ppnt[nbatch],
					     ppnt[nbatch],
					     pbatchinc,
					     vxcp->vxc_bnctx);
			}
		}

		/*
		 * The single most expensive operation performed in this
		 * loop is modular inversion of ppnt->Z.  There is an
		 * algorithm implemented in OpenSSL to do batched inversion
		 * that only does one actual BN_mod_inverse(), and saves
		 * a _lot_ of time.
		 *
		 * To take advantage of this, we batch up a few points,
		 * and feed them to EC_POINTs_make_affine() below.
		 */

		EC_POINTs_make_affine(pgroup, nbatch, ppnt, vxcp->vxc_bnctx);

		for (i = 0; i < nbatch; i++, vxcp->vxc_delta++) {
			/* Hash the public key */
			len = EC_POINT_point2oct(pgroup, ppnt[i],
						 POINT_CONVERSION_UNCOMPRESSED,
						 eckey_buf,
						 65,
						 vxcp->vxc_bnctx);
			assert(len == 65);

			SHA256(hash_buf, hash_len, hash1);
			RIPEMD160(hash1, sizeof(hash1), &vxcp->vxc_binres[1]);

			switch (test_func(vxcp)) {
			case 1:
				npoints = 0;
				rekey_at = 0;
				i = nbatch;
				break;
			case 2:
				goto out;
			default:
				break;
			}
		}

		c += i;
		if (c >= output_interval) {
			output_interval = vg_output_timing(vcp, c, &tvstart);
			if (output_interval > 250000)
				output_interval = 250000;
			c = 0;
		}

		vg_exec_context_yield(vxcp);
	}

out:
	vg_exec_context_del(&ctx);
	vg_context_thread_exit(vcp);

	for (i = 0; i < ptarraysize; i++)
		if (ppnt[i])
			EC_POINT_free(ppnt[i]);
	if (pbatchinc)
		EC_POINT_free(pbatchinc);
	return NULL;
}


#if !defined(WIN32)
int
count_processors(void)
{
	FILE *fp;
	char buf[512];
	int count = 0;

	fp = fopen("/proc/cpuinfo", "r");
	if (!fp)
		return -1;

	while (fgets(buf, sizeof(buf), fp)) {
		if (!strncmp(buf, "processor\t", 10))
			count += 1;
	}
	fclose(fp);
	return count;
}
#endif

int
start_threads(vg_context_t *vcp, int nthreads)
{
	pthread_t thread;

	if (nthreads <= 0) {
		/* Determine the number of threads */
		nthreads = count_processors();
		if (nthreads <= 0) {
#ifdef VANITY_MAIN
			fprintf(stderr,
				"ERROR: could not determine processor count\n");
#endif
            nthreads = 1;
		}
	}

	if (vcp->vc_verbose > 1) {
		fprintf(stderr, "Using %d worker thread(s)\n", nthreads);
	}

	while (--nthreads) {
		if (pthread_create(&thread, NULL, vg_thread_loop, vcp))
			return 0;
	}

	vg_thread_loop(vcp);
	return 1;
}

// patterns.c

/*
 * Common code for execution helper
 */

EC_KEY *
vg_exec_context_new_key(void)
{
    return EC_KEY_new_by_curve_name(NID_secp256k1);
}

/*
 * Thread synchronization helpers
 */

static pthread_mutex_t vg_thread_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t vg_thread_rdcond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t vg_thread_wrcond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t vg_thread_upcond = PTHREAD_COND_INITIALIZER;

static void
__vg_exec_context_yield(vg_exec_context_t *vxcp)
{
    vxcp->vxc_lockmode = 0;
    while (vxcp->vxc_vc->vc_thread_excl) {
        if (vxcp->vxc_stop) {
            assert(vxcp->vxc_vc->vc_thread_excl);
            vxcp->vxc_stop = 0;
            pthread_cond_signal(&vg_thread_upcond);
        }
        pthread_cond_wait(&vg_thread_rdcond, &vg_thread_lock);
    }
    assert(!vxcp->vxc_stop);
    assert(!vxcp->vxc_lockmode);
    vxcp->vxc_lockmode = 1;
}

int
vg_exec_context_upgrade_lock(vg_exec_context_t *vxcp)
{
    vg_exec_context_t *tp;
    vg_context_t *vcp;

    if (vxcp->vxc_lockmode == 2)
        return 0;

    pthread_mutex_lock(&vg_thread_lock);

    assert(vxcp->vxc_lockmode == 1);
    vxcp->vxc_lockmode = 0;
    vcp = vxcp->vxc_vc;

    if (vcp->vc_thread_excl++) {
        assert(vxcp->vxc_stop);
        vxcp->vxc_stop = 0;
        pthread_cond_signal(&vg_thread_upcond);
        pthread_cond_wait(&vg_thread_wrcond, &vg_thread_lock);

        for (tp = vcp->vc_threads; tp != NULL; tp = tp->vxc_next) {
            assert(!tp->vxc_lockmode);
            assert(!tp->vxc_stop);
        }

    } else {
        for (tp = vcp->vc_threads; tp != NULL; tp = tp->vxc_next) {
            if (tp->vxc_lockmode) {
                assert(tp->vxc_lockmode != 2);
                tp->vxc_stop = 1;
            }
        }

        do {
            for (tp = vcp->vc_threads;
                 tp != NULL;
                 tp = tp->vxc_next) {
                if (tp->vxc_lockmode) {
                    assert(tp->vxc_lockmode != 2);
                    pthread_cond_wait(&vg_thread_upcond,
                              &vg_thread_lock);
                    break;
                }
            }
        } while (tp);
    }

    vxcp->vxc_lockmode = 2;
    pthread_mutex_unlock(&vg_thread_lock);
    return 1;
}

void
vg_exec_context_downgrade_lock(vg_exec_context_t *vxcp)
{
    pthread_mutex_lock(&vg_thread_lock);
    assert(vxcp->vxc_lockmode == 2);
    assert(!vxcp->vxc_stop);
    if (!--vxcp->vxc_vc->vc_thread_excl) {
        vxcp->vxc_lockmode = 1;
        pthread_cond_broadcast(&vg_thread_rdcond);
        pthread_mutex_unlock(&vg_thread_lock);
        return;
    }
    pthread_cond_signal(&vg_thread_wrcond);
    __vg_exec_context_yield(vxcp);
    pthread_mutex_unlock(&vg_thread_lock);
}

int
vg_exec_context_init(vg_context_t *vcp, vg_exec_context_t *vxcp)
{
    pthread_mutex_lock(&vg_thread_lock);

    memset(vxcp, 0, sizeof(*vxcp));

    vxcp->vxc_vc = vcp;

    BN_init(&vxcp->vxc_bntarg);
    BN_init(&vxcp->vxc_bnbase);
    BN_init(&vxcp->vxc_bntmp);
    BN_init(&vxcp->vxc_bntmp2);

    BN_set_word(&vxcp->vxc_bnbase, 58);

    vxcp->vxc_bnctx = BN_CTX_new();
    assert(vxcp->vxc_bnctx);
    vxcp->vxc_key = vg_exec_context_new_key();
    assert(vxcp->vxc_key);
    EC_KEY_precompute_mult(vxcp->vxc_key, vxcp->vxc_bnctx);

    vxcp->vxc_lockmode = 0;
    vxcp->vxc_stop = 0;

    vxcp->vxc_next = vcp->vc_threads;
    vcp->vc_threads = vxcp;
    __vg_exec_context_yield(vxcp);
    pthread_mutex_unlock(&vg_thread_lock);
    return 1;
}

void
vg_exec_context_del(vg_exec_context_t *vxcp)
{
    vg_exec_context_t *tp, **pprev;

    if (vxcp->vxc_lockmode == 2)
        vg_exec_context_downgrade_lock(vxcp);

    pthread_mutex_lock(&vg_thread_lock);
    assert(vxcp->vxc_lockmode == 1);
    vxcp->vxc_lockmode = 0;

    for (pprev = &vxcp->vxc_vc->vc_threads, tp = *pprev;
         (tp != vxcp) && (tp != NULL);
         pprev = &tp->vxc_next, tp = *pprev);

    assert(tp == vxcp);
    *pprev = tp->vxc_next;

    if (tp->vxc_stop)
        pthread_cond_signal(&vg_thread_upcond);

    BN_clear_free(&vxcp->vxc_bntarg);
    BN_clear_free(&vxcp->vxc_bnbase);
    BN_clear_free(&vxcp->vxc_bntmp);
    BN_clear_free(&vxcp->vxc_bntmp2);
    BN_CTX_free(vxcp->vxc_bnctx);
    vxcp->vxc_bnctx = NULL;
    pthread_mutex_unlock(&vg_thread_lock);
}

void
vg_exec_context_yield(vg_exec_context_t *vxcp)
{
    if (vxcp->vxc_lockmode == 2)
        vg_exec_context_downgrade_lock(vxcp);

    else if (vxcp->vxc_stop) {
        assert(vxcp->vxc_lockmode == 1);
        pthread_mutex_lock(&vg_thread_lock);
        __vg_exec_context_yield(vxcp);
        pthread_mutex_unlock(&vg_thread_lock);
    }

    assert(vxcp->vxc_lockmode == 1);
}

void
vg_exec_context_consolidate_key(vg_exec_context_t *vxcp)
{
    if (vxcp->vxc_delta) {
        BN_clear(&vxcp->vxc_bntmp);
        BN_set_word(&vxcp->vxc_bntmp, vxcp->vxc_delta);
        BN_add(&vxcp->vxc_bntmp2,
               EC_KEY_get0_private_key(vxcp->vxc_key),
               &vxcp->vxc_bntmp);
        vg_set_privkey(&vxcp->vxc_bntmp2, vxcp->vxc_key);
        vxcp->vxc_delta = 0;
    }
}

void
vg_exec_context_calc_address(vg_exec_context_t *vxcp)
{
    EC_POINT *pubkey;
    const EC_GROUP *pgroup;
    unsigned char eckey_buf[96], hash1[32], hash2[20];
    int len;

    vg_exec_context_consolidate_key(vxcp);
    pgroup = EC_KEY_get0_group(vxcp->vxc_key);
    pubkey = EC_POINT_new(pgroup);
    EC_POINT_copy(pubkey, EC_KEY_get0_public_key(vxcp->vxc_key));
    if (vxcp->vxc_vc->vc_pubkey_base) {
        EC_POINT_add(pgroup,
                 pubkey,
                 pubkey,
                 vxcp->vxc_vc->vc_pubkey_base,
                 vxcp->vxc_bnctx);
    }
    len = EC_POINT_point2oct(pgroup,
                 pubkey,
                 POINT_CONVERSION_UNCOMPRESSED,
                 eckey_buf,
                 sizeof(eckey_buf),
                 vxcp->vxc_bnctx);
    SHA256(eckey_buf, len, hash1);
    RIPEMD160(hash1, sizeof(hash1), hash2);
    memcpy(&vxcp->vxc_binres[1],
           hash2, 20);
    EC_POINT_free(pubkey);
}

enum {
    timing_hist_size = 5
};

typedef struct _timing_info_s {
    struct _timing_info_s	*ti_next;
    pthread_t		ti_thread;
    unsigned long		ti_last_rate;

    unsigned long long	ti_hist_time[timing_hist_size];
    unsigned long		ti_hist_work[timing_hist_size];
    int			ti_hist_last;
} timing_info_t;

static pthread_mutex_t timing_mutex = PTHREAD_MUTEX_INITIALIZER;

int
vg_output_timing(vg_context_t *vcp, int cycle, struct timeval *last)
{
    pthread_t me;
    struct timeval tvnow, tv;
    timing_info_t *tip, *mytip;
    unsigned long long rate, myrate = 0, mytime, total, sincelast;
    int p, i;

    /* Compute the rate */
    gettimeofday(&tvnow, NULL);
    timersub(&tvnow, last, &tv);
    memcpy(last, &tvnow, sizeof(*last));
    mytime = tv.tv_usec + (1000000ULL * tv.tv_sec);
    if (!mytime)
        mytime = 1;
    rate = 0;

    pthread_mutex_lock(&timing_mutex);
    me = pthread_self();
    for (tip = vcp->vc_timing_head, mytip = NULL;
         tip != NULL; tip = tip->ti_next) {
        if (pthread_equal(tip->ti_thread, me)) {
            mytip = tip;
            p = ((tip->ti_hist_last + 1) % timing_hist_size);
            tip->ti_hist_time[p] = mytime;
            tip->ti_hist_work[p] = cycle;
            tip->ti_hist_last = p;

            mytime = 0;
            myrate = 0;
            for (i = 0; i < timing_hist_size; i++) {
                mytime += tip->ti_hist_time[i];
                myrate += tip->ti_hist_work[i];
            }
            myrate = (myrate * 1000000) / mytime;
            tip->ti_last_rate = myrate;
            rate += myrate;

        } else
            rate += tip->ti_last_rate;
    }
    if (!mytip) {
        mytip = (timing_info_t *) malloc(sizeof(*tip));
        mytip->ti_next = vcp->vc_timing_head;
        mytip->ti_thread = me;
        vcp->vc_timing_head = mytip;
        mytip->ti_hist_last = 0;
        mytip->ti_hist_time[0] = mytime;
        mytip->ti_hist_work[0] = cycle;
        for (i = 1; i < timing_hist_size; i++) {
            mytip->ti_hist_time[i] = 1;
            mytip->ti_hist_work[i] = 0;
        }
        myrate = ((unsigned long long)cycle * 1000000) / mytime;
        mytip->ti_last_rate = myrate;
        rate += myrate;
    }

    vcp->vc_timing_total += cycle;
    if (vcp->vc_timing_prevfound != vcp->vc_found) {
        vcp->vc_timing_prevfound = vcp->vc_found;
        vcp->vc_timing_sincelast = 0;
    }
    vcp->vc_timing_sincelast += cycle;

    if (mytip != vcp->vc_timing_head) {
        pthread_mutex_unlock(&timing_mutex);
        return myrate;
    }
    total = vcp->vc_timing_total;
    sincelast = vcp->vc_timing_sincelast;
    pthread_mutex_unlock(&timing_mutex);

    vcp->vc_output_timing(vcp, sincelast, rate, total);
    return myrate;
}

void
vg_context_thread_exit(vg_context_t *vcp)
{
    timing_info_t *tip, **ptip;
    pthread_t me;

    pthread_mutex_lock(&timing_mutex);
    me = pthread_self();
    for (ptip = &vcp->vc_timing_head, tip = *ptip;
         tip != NULL;
         ptip = &tip->ti_next, tip = *ptip) {
        if (!pthread_equal(tip->ti_thread, me))
            continue;
        *ptip = tip->ti_next;
        free(tip);
        break;
    }
    pthread_mutex_unlock(&timing_mutex);

}

static void
vg_timing_info_free(vg_context_t *vcp)
{
    timing_info_t *tp;
    while (vcp->vc_timing_head != NULL) {
        tp = vcp->vc_timing_head;
        vcp->vc_timing_head = tp->ti_next;
        free(tp);
    }
}

void
vg_output_timing_console(vg_context_t *vcp, double count,
             unsigned long long rate, unsigned long long total)
{
    double prob, time, targ;
    char *unit;
    char linebuf[80];
    int rem, p, i;

    const double targs[] = { 0.5, 0.75, 0.8, 0.9, 0.95, 1.0 };

    targ = rate;
    unit = "key/s";
    if (targ > 1000) {
        unit = "Kkey/s";
        targ /= 1000.0;
        if (targ > 1000) {
            unit = "Mkey/s";
            targ /= 1000.0;
        }
    }

    rem = sizeof(linebuf);
    p = snprintf(linebuf, rem, "[%.2f %s][total %lld]",
             targ, unit, total);
    assert(p > 0);
    rem -= p;
    if (rem < 0)
        rem = 0;

    if (vcp->vc_chance >= 1.0) {
        prob = 1.0f - exp(-count/vcp->vc_chance);

        if (prob <= 0.999) {
            p = snprintf(&linebuf[p], rem, "[Prob %.1f%%]",
                     prob * 100);
            assert(p > 0);
            rem -= p;
            if (rem < 0)
                rem = 0;
            p = sizeof(linebuf) - rem;
        }

        for (i = 0; i < sizeof(targs)/sizeof(targs[0]); i++) {
            targ = targs[i];
            if ((targ < 1.0) && (prob <= targ))
                break;
        }

        if (targ < 1.0) {
            time = ((-vcp->vc_chance * log(1.0 - targ)) - count) /
                rate;
            unit = "s";
            if (time > 60) {
                time /= 60;
                unit = "min";
                if (time > 60) {
                    time /= 60;
                    unit = "h";
                    if (time > 24) {
                        time /= 24;
                        unit = "d";
                        if (time > 365) {
                            time /= 365;
                            unit = "y";
                        }
                    }
                }
            }

            if (time > 1000000) {
                p = snprintf(&linebuf[p], rem,
                         "[%d%% in %e%s]",
                         (int) (100 * targ), time, unit);
            } else {
                p = snprintf(&linebuf[p], rem,
                         "[%d%% in %.1f%s]",
                         (int) (100 * targ), time, unit);
            }
            assert(p > 0);
            rem -= p;
            if (rem < 0)
                rem = 0;
            p = sizeof(linebuf) - rem;
        }
    }

    if (vcp->vc_found) {
        if (vcp->vc_remove_on_match)
            p = snprintf(&linebuf[p], rem, "[Found %lld/%ld]",
                     vcp->vc_found, vcp->vc_npatterns_start);
        else
            p = snprintf(&linebuf[p], rem, "[Found %lld]",
                     vcp->vc_found);
        assert(p > 0);
        rem -= p;
        if (rem < 0)
            rem = 0;
    }

    if (rem) {
        memset(&linebuf[sizeof(linebuf)-rem], 0x20, rem);
        linebuf[sizeof(linebuf)-1] = '\0';
    }
#ifdef VANITY_MAIN
    printf("\r%s", linebuf);
    fflush(stdout);
#endif
}

void
vg_output_match_console(vg_context_t *vcp, EC_KEY *pkey, const char *pattern)
{
    unsigned char key_buf[512], *pend;
    char addr_buf[64], addr2_buf[64];
    char privkey_buf[VG_PROTKEY_MAX_B58];
    const char *keytype = "Privkey";
    int len;
    int isscript = (vcp->vc_format == VCF_SCRIPT);

    EC_POINT *ppnt;
    int free_ppnt = 0;
    if (vcp->vc_pubkey_base) {
        ppnt = EC_POINT_new(EC_KEY_get0_group(pkey));
        EC_POINT_copy(ppnt, EC_KEY_get0_public_key(pkey));
        EC_POINT_add(EC_KEY_get0_group(pkey),
                 ppnt,
                 ppnt,
                 vcp->vc_pubkey_base,
                 NULL);
        free_ppnt = 1;
        keytype = "PrivkeyPart";
    } else {
        ppnt = (EC_POINT *) EC_KEY_get0_public_key(pkey);
    }

    assert(EC_KEY_check_key(pkey));
    vg_encode_address(ppnt,
              EC_KEY_get0_group(pkey),
              vcp->vc_pubkeytype, addr_buf);
    if (isscript)
        vg_encode_script_address(ppnt,
                     EC_KEY_get0_group(pkey),
                     vcp->vc_addrtype, addr2_buf);

    if (vcp->vc_key_protect_pass) {
        len = vg_protect_encode_privkey(privkey_buf,
                        pkey, vcp->vc_privtype,
                        VG_PROTKEY_DEFAULT,
                        vcp->vc_key_protect_pass);
        if (len) {
            keytype = "Protkey";
        } else {
            fprintf(stderr,
                "ERROR: could not password-protect key\n");
            vcp->vc_key_protect_pass = NULL;
        }
    }
    if (!vcp->vc_key_protect_pass) {
        vg_encode_privkey(pkey, vcp->vc_privtype, privkey_buf);
    }

#ifdef VANITY_MAIN
    if (!vcp->vc_result_file || (vcp->vc_verbose > 0)) {
        printf("\r%79s\rPattern: %s\n", "", pattern);
    }
#endif
    if (vcp->vc_verbose > 0) {
        if (vcp->vc_verbose > 1) {
            pend = key_buf;
            len = i2o_ECPublicKey(pkey, &pend);
            printf("Pubkey (hex): ");
            dumphex(key_buf, len);
            printf("Privkey (hex): ");
            dumpbn(EC_KEY_get0_private_key(pkey));
            pend = key_buf;
            len = i2d_ECPrivateKey(pkey, &pend);
            printf("Privkey (ASN1): ");
            dumphex(key_buf, len);
        }

    }

    if (!vcp->vc_result_file || (vcp->vc_verbose > 0)) {
        if (isscript)
            printf("P2SHAddress: %s\n", addr2_buf);
        printf("Address: %s\n"
               "%s: %s\n",
               addr_buf, keytype, privkey_buf);
    }

// make this available for the VanityGen function

    strcpy(VG_PUB_KEY_BUF, addr_buf);
    strcpy(VG_PRV_KEY_BUF, privkey_buf);

    if (vcp->vc_result_file) {
        FILE *fp = fopen(vcp->vc_result_file, "a");
        if (!fp) {
            fprintf(stderr,
                "ERROR: could not open result file: %s\n",
                strerror(errno));
        } else {
            fprintf(fp,
                "Pattern: %s\n"
                , pattern);
            if (isscript)
                fprintf(fp, "P2SHAddress: %s\n", addr2_buf);
            fprintf(fp,
                "Address: %s\n"
                "%s: %s\n",
                addr_buf, keytype, privkey_buf);
            fclose(fp);
        }
    }
    if (free_ppnt)
        EC_POINT_free(ppnt);
}


void
vg_context_free(vg_context_t *vcp)
{
    vg_timing_info_free(vcp);
    vcp->vc_free(vcp);
}

int
vg_context_add_patterns(vg_context_t *vcp,
            const char ** const patterns, int npatterns)
{
    vcp->vc_pattern_generation++;
    return vcp->vc_add_patterns(vcp, patterns, npatterns);
}

void
vg_context_clear_all_patterns(vg_context_t *vcp)
{
    vcp->vc_clear_all_patterns(vcp);
    vcp->vc_pattern_generation++;
}

int
vg_context_hash160_sort(vg_context_t *vcp, void *buf)
{
    if (!vcp->vc_hash160_sort)
        return 0;
    return vcp->vc_hash160_sort(vcp, buf);
}

int
vg_context_start_threads(vg_context_t *vcp)
{
    vg_exec_context_t *vxcp;
    int res;

    for (vxcp = vcp->vc_threads; vxcp != NULL; vxcp = vxcp->vxc_next) {
        res = pthread_create((pthread_t *) &vxcp->vxc_pthread,
                     NULL,
                     (void *(*)(void *)) vxcp->vxc_threadfunc,
                     vxcp);
        if (res) {
            fprintf(stderr, "ERROR: could not create thread: %d\n",
                res);
            vg_context_stop_threads(vcp);
            return -1;
        }
        vxcp->vxc_thread_active = 1;
    }
    return 0;
}

void
vg_context_stop_threads(vg_context_t *vcp)
{
    vcp->vc_halt = 1;
    vg_context_wait_for_completion(vcp);
    vcp->vc_halt = 0;
}

void
vg_context_wait_for_completion(vg_context_t *vcp)
{
    vg_exec_context_t *vxcp;

    for (vxcp = vcp->vc_threads; vxcp != NULL; vxcp = vxcp->vxc_next) {
        if (!vxcp->vxc_thread_active)
            continue;
        pthread_join((pthread_t) vxcp->vxc_pthread, NULL);
        vxcp->vxc_thread_active = 0;
    }
}


/*
 * Find the bignum ranges that produce a given prefix.
 */
static int
get_prefix_ranges(int addrtype, const char *pfx, BIGNUM **result,
          BN_CTX *bnctx)
{
    int i, p, c;
    int zero_prefix = 0;
    int check_upper = 0;
    int b58pow, b58ceil, b58top = 0;
    int ret = -1;

    BIGNUM bntarg, bnceil, bnfloor;
    BIGNUM bnbase;
    BIGNUM *bnap, *bnbp, *bntp;
    BIGNUM *bnhigh = NULL, *bnlow = NULL, *bnhigh2 = NULL, *bnlow2 = NULL;
    BIGNUM bntmp, bntmp2;

    BN_init(&bntarg);
    BN_init(&bnceil);
    BN_init(&bnfloor);
    BN_init(&bnbase);
    BN_init(&bntmp);
    BN_init(&bntmp2);

    BN_set_word(&bnbase, 58);

    p = strlen(pfx);

    for (i = 0; i < p; i++) {
        c = vg_b58_reverse_map[(int)pfx[i]];
        if (c == -1) {
            fprintf(stderr,
                "Invalid character '%c' in prefix '%s'\n",
                pfx[i], pfx);
            goto out;
        }
        if (i == zero_prefix) {
            if (c == 0) {
                /* Add another zero prefix */
                zero_prefix++;
                if (zero_prefix > 19) {
                    fprintf(stderr,
                        "Prefix '%s' is too long\n",
                        pfx);
                    goto out;
                }
                continue;
            }

            /* First non-zero character */
            b58top = c;
            BN_set_word(&bntarg, c);

        } else {
            BN_set_word(&bntmp2, c);
            BN_mul(&bntmp, &bntarg, &bnbase, bnctx);
            BN_add(&bntarg, &bntmp, &bntmp2);
        }
    }

    /* Power-of-two ceiling and floor values based on leading 1s */
    BN_clear(&bntmp);
    BN_set_bit(&bntmp, 200 - (zero_prefix * 8));
    BN_sub(&bnceil, &bntmp, BN_value_one());
    BN_set_bit(&bnfloor, 192 - (zero_prefix * 8));

    bnlow = BN_new();
    bnhigh = BN_new();

    if (b58top) {
        /*
         * If a non-zero was given in the prefix, find the
         * numeric boundaries of the prefix.
         */

        BN_copy(&bntmp, &bnceil);
        bnap = &bntmp;
        bnbp = &bntmp2;
        b58pow = 0;
        while (BN_cmp(bnap, &bnbase) > 0) {
            b58pow++;
            BN_div(bnbp, NULL, bnap, &bnbase, bnctx);
            bntp = bnap;
            bnap = bnbp;
            bnbp = bntp;
        }
        b58ceil = BN_get_word(bnap);

        if ((b58pow - (p - zero_prefix)) < 6) {
            /*
             * Do not allow the prefix to constrain the
             * check value, this is ridiculous.
             */
            fprintf(stderr, "Prefix '%s' is too long\n", pfx);
            goto out;
        }

        BN_set_word(&bntmp2, b58pow - (p - zero_prefix));
        BN_exp(&bntmp, &bnbase, &bntmp2, bnctx);
        BN_mul(bnlow, &bntmp, &bntarg, bnctx);
        BN_sub(&bntmp2, &bntmp, BN_value_one());
        BN_add(bnhigh, bnlow, &bntmp2);

        if (b58top <= b58ceil) {
            /* Fill out the upper range too */
            check_upper = 1;
            bnlow2 = BN_new();
            bnhigh2 = BN_new();

            BN_mul(bnlow2, bnlow, &bnbase, bnctx);
            BN_mul(&bntmp2, bnhigh, &bnbase, bnctx);
            BN_set_word(&bntmp, 57);
            BN_add(bnhigh2, &bntmp2, &bntmp);

            /*
             * Addresses above the ceiling will have one
             * fewer "1" prefix in front than we require.
             */
            if (BN_cmp(&bnceil, bnlow2) < 0) {
                /* High prefix is above the ceiling */
                check_upper = 0;
                BN_free(bnhigh2);
                bnhigh2 = NULL;
                BN_free(bnlow2);
                bnlow2 = NULL;
            }
            else if (BN_cmp(&bnceil, bnhigh2) < 0)
                /* High prefix is partly above the ceiling */
                BN_copy(bnhigh2, &bnceil);

            /*
             * Addresses below the floor will have another
             * "1" prefix in front instead of our target.
             */
            if (BN_cmp(&bnfloor, bnhigh) >= 0) {
                /* Low prefix is completely below the floor */
                assert(check_upper);
                check_upper = 0;
                BN_free(bnhigh);
                bnhigh = bnhigh2;
                bnhigh2 = NULL;
                BN_free(bnlow);
                bnlow = bnlow2;
                bnlow2 = NULL;
            }
            else if (BN_cmp(&bnfloor, bnlow) > 0) {
                /* Low prefix is partly below the floor */
                BN_copy(bnlow, &bnfloor);
            }
        }

    } else {
        BN_copy(bnhigh, &bnceil);
        BN_clear(bnlow);
    }

    /* Limit the prefix to the address type */
    BN_clear(&bntmp);
    BN_set_word(&bntmp, addrtype);
    BN_lshift(&bntmp2, &bntmp, 192);

    if (check_upper) {
        if (BN_cmp(&bntmp2, bnhigh2) > 0) {
            check_upper = 0;
            BN_free(bnhigh2);
            bnhigh2 = NULL;
            BN_free(bnlow2);
            bnlow2 = NULL;
        }
        else if (BN_cmp(&bntmp2, bnlow2) > 0)
            BN_copy(bnlow2, &bntmp2);
    }

    if (BN_cmp(&bntmp2, bnhigh) > 0) {
        if (!check_upper)
            goto not_possible;
        check_upper = 0;
        BN_free(bnhigh);
        bnhigh = bnhigh2;
        bnhigh2 = NULL;
        BN_free(bnlow);
        bnlow = bnlow2;
        bnlow2 = NULL;
    }
    else if (BN_cmp(&bntmp2, bnlow) > 0) {
        BN_copy(bnlow, &bntmp2);
    }

    BN_set_word(&bntmp, addrtype + 1);
    BN_lshift(&bntmp2, &bntmp, 192);

    if (check_upper) {
        if (BN_cmp(&bntmp2, bnlow2) < 0) {
            check_upper = 0;
            BN_free(bnhigh2);
            bnhigh2 = NULL;
            BN_free(bnlow2);
            bnlow2 = NULL;
        }
        else if (BN_cmp(&bntmp2, bnhigh2) < 0)
            BN_copy(bnlow2, &bntmp2);
    }

    if (BN_cmp(&bntmp2, bnlow) < 0) {
        if (!check_upper)
            goto not_possible;
        check_upper = 0;
        BN_free(bnhigh);
        bnhigh = bnhigh2;
        bnhigh2 = NULL;
        BN_free(bnlow);
        bnlow = bnlow2;
        bnlow2 = NULL;
    }
    else if (BN_cmp(&bntmp2, bnhigh) < 0) {
        BN_copy(bnhigh, &bntmp2);
    }

    /* Address ranges are complete */
    assert(check_upper || ((bnlow2 == NULL) && (bnhigh2 == NULL)));
    result[0] = bnlow;
    result[1] = bnhigh;
    result[2] = bnlow2;
    result[3] = bnhigh2;
    bnlow = NULL;
    bnhigh = NULL;
    bnlow2 = NULL;
    bnhigh2 = NULL;
    ret = 0;

    if (0) {
    not_possible:
        ret = -2;
    }

out:
    BN_clear_free(&bntarg);
    BN_clear_free(&bnceil);
    BN_clear_free(&bnfloor);
    BN_clear_free(&bnbase);
    BN_clear_free(&bntmp);
    BN_clear_free(&bntmp2);
    if (bnhigh)
        BN_free(bnhigh);
    if (bnlow)
        BN_free(bnlow);
    if (bnhigh2)
        BN_free(bnhigh2);
    if (bnlow2)
        BN_free(bnlow2);

    return ret;
}

static void
free_ranges(BIGNUM **ranges)
{
    BN_free(ranges[0]);
    BN_free(ranges[1]);
    ranges[0] = NULL;
    ranges[1] = NULL;
    if (ranges[2]) {
        BN_free(ranges[2]);
        BN_free(ranges[3]);
        ranges[2] = NULL;
        ranges[3] = NULL;
    }
}


/*
 * Address prefix AVL tree node
 */

const int vpk_nwords = (25 + sizeof(BN_ULONG) - 1) / sizeof(BN_ULONG);

typedef struct _vg_prefix_s {
    avl_item_t		vp_item;
    struct _vg_prefix_s	*vp_sibling;
    const char		*vp_pattern;
    BIGNUM			*vp_low;
    BIGNUM			*vp_high;
} vg_prefix_t;

static void
vg_prefix_free(vg_prefix_t *vp)
{
    if (vp->vp_low)
        BN_free(vp->vp_low);
    if (vp->vp_high)
        BN_free(vp->vp_high);
    free(vp);
}

static vg_prefix_t *
vg_prefix_avl_search(avl_root_t *rootp, BIGNUM *targ)
{
    vg_prefix_t *vp;
    avl_item_t *itemp = rootp->ar_root;

    while (itemp) {
        vp = avl_item_entry(itemp, vg_prefix_t, vp_item);
        if (BN_cmp(vp->vp_low, targ) > 0) {
            itemp = itemp->ai_left;
        } else {
            if (BN_cmp(vp->vp_high, targ) < 0) {
                itemp = itemp->ai_right;
            } else
                return vp;
        }
    }
    return NULL;
}

static vg_prefix_t *
vg_prefix_avl_insert(avl_root_t *rootp, vg_prefix_t *vpnew)
{
    vg_prefix_t *vp;
    avl_item_t *itemp = NULL;
    avl_item_t **ptrp = &rootp->ar_root;
    while (*ptrp) {
        itemp = *ptrp;
        vp = avl_item_entry(itemp, vg_prefix_t, vp_item);
        if (BN_cmp(vp->vp_low, vpnew->vp_high) > 0) {
            ptrp = &itemp->ai_left;
        } else {
            if (BN_cmp(vp->vp_high, vpnew->vp_low) < 0) {
                ptrp = &itemp->ai_right;
            } else
                return vp;
        }
    }
    vpnew->vp_item.ai_up = itemp;
    itemp = &vpnew->vp_item;
    *ptrp = itemp;
    avl_insert_fix(rootp, itemp);
    return NULL;
}

static vg_prefix_t *
vg_prefix_first(avl_root_t *rootp)
{
    avl_item_t *itemp;
    itemp = avl_first(rootp);
    if (itemp)
        return avl_item_entry(itemp, vg_prefix_t, vp_item);
    return NULL;
}

static vg_prefix_t *
vg_prefix_next(vg_prefix_t *vp)
{
    avl_item_t *itemp = &vp->vp_item;
    itemp = avl_next(itemp);
    if (itemp)
        return avl_item_entry(itemp, vg_prefix_t, vp_item);
    return NULL;
}

static vg_prefix_t *
vg_prefix_add(avl_root_t *rootp, const char *pattern, BIGNUM *low, BIGNUM *high)
{
    vg_prefix_t *vp, *vp2;
    assert(BN_cmp(low, high) < 0);
    vp = (vg_prefix_t *) malloc(sizeof(*vp));
    if (vp) {
        avl_item_init(&vp->vp_item);
        vp->vp_sibling = NULL;
        vp->vp_pattern = pattern;
        vp->vp_low = low;
        vp->vp_high = high;
        vp2 = vg_prefix_avl_insert(rootp, vp);
        if (vp2 != NULL) {
            fprintf(stderr,
                "Prefix '%s' ignored, overlaps '%s'\n",
                pattern, vp2->vp_pattern);
            vg_prefix_free(vp);
            vp = NULL;
        }
    }
    return vp;
}

static void
vg_prefix_delete(avl_root_t *rootp, vg_prefix_t *vp)
{
    vg_prefix_t *sibp, *delp;

    avl_remove(rootp, &vp->vp_item);
    sibp = vp->vp_sibling;
    while (sibp && sibp != vp) {
        avl_remove(rootp, &sibp->vp_item);
        delp = sibp;
        sibp = sibp->vp_sibling;
        vg_prefix_free(delp);
    }
    vg_prefix_free(vp);
}

static vg_prefix_t *
vg_prefix_add_ranges(avl_root_t *rootp, const char *pattern, BIGNUM **ranges,
             vg_prefix_t *master)
{
    vg_prefix_t *vp, *vp2 = NULL;

    assert(ranges[0]);
    vp = vg_prefix_add(rootp, pattern, ranges[0], ranges[1]);
    if (!vp)
        return NULL;

    if (ranges[2]) {
        vp2 = vg_prefix_add(rootp, pattern, ranges[2], ranges[3]);
        if (!vp2) {
            vg_prefix_delete(rootp, vp);
            return NULL;
        }
    }

    if (!master) {
        vp->vp_sibling = vp2;
        if (vp2)
            vp2->vp_sibling = vp;
    } else if (vp2) {
        vp->vp_sibling = vp2;
        vp2->vp_sibling = (master->vp_sibling ?
                   master->vp_sibling :
                   master);
        master->vp_sibling = vp;
    } else {
        vp->vp_sibling = (master->vp_sibling ?
                  master->vp_sibling :
                  master);
        master->vp_sibling = vp;
    }
    return vp;
}

static void
vg_prefix_range_sum(vg_prefix_t *vp, BIGNUM *result, BIGNUM *tmp1)
{
    vg_prefix_t *startp;

    startp = vp;
    BN_clear(result);
    do {
        BN_sub(tmp1, vp->vp_high, vp->vp_low);
        BN_add(result, result, tmp1);
        vp = vp->vp_sibling;
    } while (vp && (vp != startp));
}


typedef struct _prefix_case_iter_s {
    char	ci_prefix[32];
    char	ci_case_map[32];
    char	ci_nbits;
    int	ci_value;
} prefix_case_iter_t;

static const unsigned char b58_case_map[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 0, 1, 1, 2,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 2, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
};

static int
prefix_case_iter_init(prefix_case_iter_t *cip, const char *pfx)
{
    int i;

    cip->ci_nbits = 0;
    cip->ci_value = 0;
    for (i = 0; pfx[i]; i++) {
        if (i > sizeof(cip->ci_prefix))
            return 0;
        if (!b58_case_map[(int)pfx[i]]) {
            /* Character isn't case-swappable, ignore it */
            cip->ci_prefix[i] = pfx[i];
            continue;
        }
        if (b58_case_map[(int)pfx[i]] == 2) {
            /* Character invalid, but valid in swapped case */
            cip->ci_prefix[i] = pfx[i] ^ 0x20;
            continue;
        }
        /* Character is case-swappable */
        cip->ci_prefix[i] = pfx[i] | 0x20;
        cip->ci_case_map[(int)cip->ci_nbits] = i;
        cip->ci_nbits++;
    }
    cip->ci_prefix[i] = '\0';
    return 1;
}

static int
prefix_case_iter_next(prefix_case_iter_t *cip)
{
    unsigned long val, max, mask;
    int i, nbits;

    nbits = cip->ci_nbits;
    max = (1UL << nbits) - 1;
    val = cip->ci_value + 1;
    if (val > max)
        return 0;

    for (i = 0, mask = 1; i < nbits; i++, mask <<= 1) {
        if (val & mask)
            cip->ci_prefix[(int)cip->ci_case_map[i]] &= 0xdf;
        else
            cip->ci_prefix[(int)cip->ci_case_map[i]] |= 0x20;
    }
    cip->ci_value = val;
    return 1;
}


typedef struct _vg_prefix_context_s {
    vg_context_t		base;
    avl_root_t		vcp_avlroot;
    BIGNUM			vcp_difficulty;
    int			vcp_caseinsensitive;
} vg_prefix_context_t;

void
vg_prefix_context_set_case_insensitive(vg_context_t *vcp, int caseinsensitive)
{
    ((vg_prefix_context_t *) vcp)->vcp_caseinsensitive = caseinsensitive;
}

static void
vg_prefix_context_clear_all_patterns(vg_context_t *vcp)
{
    vg_prefix_context_t *vcpp = (vg_prefix_context_t *) vcp;
    vg_prefix_t *vp;
    unsigned long npfx_left = 0;

    while (!avl_root_empty(&vcpp->vcp_avlroot)) {
        vp = avl_item_entry(vcpp->vcp_avlroot.ar_root,
                    vg_prefix_t, vp_item);
        vg_prefix_delete(&vcpp->vcp_avlroot, vp);
        npfx_left++;
    }

    assert(npfx_left == vcpp->base.vc_npatterns);
    vcpp->base.vc_npatterns = 0;
    vcpp->base.vc_npatterns_start = 0;
    vcpp->base.vc_found = 0;
    BN_clear(&vcpp->vcp_difficulty);
}

static void
vg_prefix_context_free(vg_context_t *vcp)
{
    vg_prefix_context_t *vcpp = (vg_prefix_context_t *) vcp;
    vg_prefix_context_clear_all_patterns(vcp);
    BN_clear_free(&vcpp->vcp_difficulty);
    free(vcpp);
}

static void
vg_prefix_context_next_difficulty(vg_prefix_context_t *vcpp,
                  BIGNUM *bntmp, BIGNUM *bntmp2, BN_CTX *bnctx)
{
    char *dbuf;

    BN_clear(bntmp);
    BN_set_bit(bntmp, 192);
    BN_div(bntmp2, NULL, bntmp, &vcpp->vcp_difficulty, bnctx);

    dbuf = BN_bn2dec(bntmp2);
#ifdef VANITY_MAIN

    if (vcpp->base.vc_verbose > 0) {
        if (vcpp->base.vc_npatterns > 1)
            fprintf(stderr,
                "Next match difficulty: %s (%ld prefixes)\n",
                dbuf, vcpp->base.vc_npatterns);
        else
            fprintf(stderr, "Difficulty: %s\n", dbuf);
    }
#endif
    vcpp->base.vc_chance = atof(dbuf);
    OPENSSL_free(dbuf);
}

static int
vg_prefix_context_add_patterns(vg_context_t *vcp,
                   const char ** const patterns, int npatterns)
{
    vg_prefix_context_t *vcpp = (vg_prefix_context_t *) vcp;
    prefix_case_iter_t caseiter;
    vg_prefix_t *vp, *vp2;
    BN_CTX *bnctx;
    BIGNUM bntmp, bntmp2, bntmp3;
    BIGNUM *ranges[4];
    int ret = 0;
    int i, impossible = 0;
    int case_impossible;
    unsigned long npfx;
    char *dbuf;

    bnctx = BN_CTX_new();
    BN_init(&bntmp);
    BN_init(&bntmp2);
    BN_init(&bntmp3);

    npfx = 0;
    for (i = 0; i < npatterns; i++) {
        if (!vcpp->vcp_caseinsensitive) {
            vp = NULL;
            ret = get_prefix_ranges(vcpp->base.vc_addrtype,
                        patterns[i],
                        ranges, bnctx);
            if (!ret) {
                vp = vg_prefix_add_ranges(&vcpp->vcp_avlroot,
                              patterns[i],
                              ranges, NULL);
            }

        } else {
            /* Case-enumerate the prefix */
            if (!prefix_case_iter_init(&caseiter, patterns[i])) {
                fprintf(stderr,
                    "Prefix '%s' is too long\n",
                    patterns[i]);
                continue;
            }

            if (caseiter.ci_nbits > 16) {
                fprintf(stderr,
                    "WARNING: Prefix '%s' has "
                    "2^%d case-varied derivatives\n",
                    patterns[i], caseiter.ci_nbits);
            }

            case_impossible = 0;
            vp = NULL;
            do {
                ret = get_prefix_ranges(vcpp->base.vc_addrtype,
                            caseiter.ci_prefix,
                            ranges, bnctx);
                if (ret == -2) {
                    case_impossible++;
                    ret = 0;
                    continue;
                }
                if (ret)
                    break;
                vp2 = vg_prefix_add_ranges(&vcpp->vcp_avlroot,
                               patterns[i],
                               ranges,
                               vp);
                if (!vp2) {
                    ret = -1;
                    break;
                }
                if (!vp)
                    vp = vp2;

            } while (prefix_case_iter_next(&caseiter));

            if (!vp && case_impossible)
                ret = -2;

            if (ret && vp) {
                vg_prefix_delete(&vcpp->vcp_avlroot, vp);
                vp = NULL;
            }
        }

        if (ret == -2) {
            fprintf(stderr,
                "Prefix '%s' not possible\n", patterns[i]);
            impossible++;
        }

        if (!vp)
            continue;

        npfx++;

        /* Determine the probability of finding a match */
        vg_prefix_range_sum(vp, &bntmp, &bntmp2);
        BN_add(&bntmp2, &vcpp->vcp_difficulty, &bntmp);
        BN_copy(&vcpp->vcp_difficulty, &bntmp2);

        if (vcp->vc_verbose > 1) {
            BN_clear(&bntmp2);
            BN_set_bit(&bntmp2, 192);
            BN_div(&bntmp3, NULL, &bntmp2, &bntmp, bnctx);

            dbuf = BN_bn2dec(&bntmp3);
            fprintf(stderr,
                "Prefix difficulty: %20s %s\n",
                dbuf, patterns[i]);
            OPENSSL_free(dbuf);
        }
    }

    vcpp->base.vc_npatterns += npfx;
    vcpp->base.vc_npatterns_start += npfx;

    if (!npfx && impossible) {
        const char *ats = "bitcoin", *bw = "\"1\"";
        switch (vcpp->base.vc_addrtype) {
        case 5:
            ats = "bitcoin script";
            bw = "\"3\"";
            break;
        case 39:
            ats = "2GIVE";
            bw = "\"G\"";
            break;
        case 111:
            ats = "testnet";
            bw = "\"m\" or \"n\"";
            break;
        case 52:
            ats = "namecoin";
            bw = "\"M\" or \"N\"";
            break;
        default:
            break;
        }
        fprintf(stderr,
            "Hint: valid %s addresses begin with %s\n", ats, bw);
    }

    if (npfx)
        vg_prefix_context_next_difficulty(vcpp, &bntmp, &bntmp2, bnctx);

    ret = (npfx != 0);

    BN_clear_free(&bntmp);
    BN_clear_free(&bntmp2);
    BN_clear_free(&bntmp3);
    BN_CTX_free(bnctx);
    return ret;
}

double
vg_prefix_get_difficulty(int addrtype, const char *pattern)
{
    BN_CTX *bnctx;
    BIGNUM result, bntmp;
    BIGNUM *ranges[4];
    char *dbuf;
    int ret;
    double diffret = 0.0;

    bnctx = BN_CTX_new();
    BN_init(&result);
    BN_init(&bntmp);

    ret = get_prefix_ranges(addrtype,
                pattern, ranges, bnctx);

    if (ret == 0) {
        BN_sub(&bntmp, ranges[1], ranges[0]);
        BN_add(&result, &result, &bntmp);
        if (ranges[2]) {
            BN_sub(&bntmp, ranges[3], ranges[2]);
            BN_add(&result, &result, &bntmp);
        }
        free_ranges(ranges);

        BN_clear(&bntmp);
        BN_set_bit(&bntmp, 192);
        BN_div(&result, NULL, &bntmp, &result, bnctx);

        dbuf = BN_bn2dec(&result);
        diffret = strtod(dbuf, NULL);
        OPENSSL_free(dbuf);
    }

    BN_clear_free(&result);
    BN_clear_free(&bntmp);
    BN_CTX_free(bnctx);
    return diffret;
}


static int
vg_prefix_test(vg_exec_context_t *vxcp)
{
    vg_prefix_context_t *vcpp = (vg_prefix_context_t *) vxcp->vxc_vc;
    vg_prefix_t *vp;
    int res = 0;

    /*
     * We constrain the prefix so that we can check for
     * a match without generating the lower four byte
     * check code.
     */

    BN_bin2bn(vxcp->vxc_binres, 25, &vxcp->vxc_bntarg);

research:
    vp = vg_prefix_avl_search(&vcpp->vcp_avlroot, &vxcp->vxc_bntarg);
    if (vp) {
        if (vg_exec_context_upgrade_lock(vxcp))
            goto research;

        vg_exec_context_consolidate_key(vxcp);
        vcpp->base.vc_output_match(&vcpp->base, vxcp->vxc_key,
                       vp->vp_pattern);

        vcpp->base.vc_found++;

        if (vcpp->base.vc_only_one) {
            return 2;
        }

        if (vcpp->base.vc_remove_on_match) {
            /* Subtract the range from the difficulty */
            vg_prefix_range_sum(vp,
                        &vxcp->vxc_bntarg,
                        &vxcp->vxc_bntmp);
            BN_sub(&vxcp->vxc_bntmp,
                   &vcpp->vcp_difficulty,
                   &vxcp->vxc_bntarg);
            BN_copy(&vcpp->vcp_difficulty, &vxcp->vxc_bntmp);

            vg_prefix_delete(&vcpp->vcp_avlroot,vp);
            vcpp->base.vc_npatterns--;

            if (!avl_root_empty(&vcpp->vcp_avlroot))
                vg_prefix_context_next_difficulty(
                    vcpp, &vxcp->vxc_bntmp,
                    &vxcp->vxc_bntmp2,
                    vxcp->vxc_bnctx);
            vcpp->base.vc_pattern_generation++;
        }
        res = 1;
    }
    if (avl_root_empty(&vcpp->vcp_avlroot)) {
        return 2;
    }
    return res;
}

static int
vg_prefix_hash160_sort(vg_context_t *vcp, void *buf)
{
    vg_prefix_context_t *vcpp = (vg_prefix_context_t *) vcp;
    vg_prefix_t *vp;
    unsigned char *cbuf = (unsigned char *) buf;
    unsigned char bnbuf[25];
    int nbytes, ncopy, nskip, npfx = 0;

    /*
     * Walk the prefix tree in order, copy the upper and lower bound
     * values into the hash160 buffer.  Skip the lower four bytes
     * and anything above the 24th byte.
     */
    for (vp = vg_prefix_first(&vcpp->vcp_avlroot);
         vp != NULL;
         vp = vg_prefix_next(vp)) {
        npfx++;
        if (!buf)
            continue;

        /* Low */
        nbytes = BN_bn2bin(vp->vp_low, bnbuf);
        ncopy = ((nbytes >= 24) ? 20 :
             ((nbytes > 4) ? (nbytes - 4) : 0));
        nskip = (nbytes >= 24) ? (nbytes - 24) : 0;
        if (ncopy < 20)
            memset(cbuf, 0, 20 - ncopy);
        memcpy(cbuf + (20 - ncopy),
               bnbuf + nskip,
               ncopy);
        cbuf += 20;

        /* High */
        nbytes = BN_bn2bin(vp->vp_high, bnbuf);
        ncopy = ((nbytes >= 24) ? 20 :
             ((nbytes > 4) ? (nbytes - 4) : 0));
        nskip = (nbytes >= 24) ? (nbytes - 24) : 0;
        if (ncopy < 20)
            memset(cbuf, 0, 20 - ncopy);
        memcpy(cbuf + (20 - ncopy),
               bnbuf + nskip,
               ncopy);
        cbuf += 20;
    }
    return npfx;
}

vg_context_t *
vg_prefix_context_new(int addrtype, int privtype, int caseinsensitive)
{
    vg_prefix_context_t *vcpp;

    vcpp = (vg_prefix_context_t *) malloc(sizeof(*vcpp));
    if (vcpp) {
        memset(vcpp, 0, sizeof(*vcpp));
        vcpp->base.vc_addrtype = addrtype;
        vcpp->base.vc_privtype = privtype;
        vcpp->base.vc_npatterns = 0;
        vcpp->base.vc_npatterns_start = 0;
        vcpp->base.vc_found = 0;
        vcpp->base.vc_chance = 0.0;
        vcpp->base.vc_free = vg_prefix_context_free;
        vcpp->base.vc_add_patterns = vg_prefix_context_add_patterns;
        vcpp->base.vc_clear_all_patterns =
            vg_prefix_context_clear_all_patterns;
        vcpp->base.vc_test = vg_prefix_test;
        vcpp->base.vc_hash160_sort = vg_prefix_hash160_sort;
        avl_root_init(&vcpp->vcp_avlroot);
        BN_init(&vcpp->vcp_difficulty);
        vcpp->vcp_caseinsensitive = caseinsensitive;
    }
    return &vcpp->base;
}




typedef struct _vg_regex_context_s {
    vg_context_t		base;
    pcre 			**vcr_regex;
    pcre_extra		**vcr_regex_extra;
    const char		**vcr_regex_pat;
    unsigned long		vcr_nalloc;
} vg_regex_context_t;

static int
vg_regex_context_add_patterns(vg_context_t *vcp,
                  const char ** const patterns, int npatterns)
{
    vg_regex_context_t *vcrp = (vg_regex_context_t *) vcp;
    const char *pcre_errptr;
    int pcre_erroffset;
    unsigned long i, nres, count;
    void **mem;

    if (!npatterns)
        return 1;

    if (npatterns > (vcrp->vcr_nalloc - vcrp->base.vc_npatterns)) {
        count = npatterns + vcrp->base.vc_npatterns;
        if (count < (2 * vcrp->vcr_nalloc)) {
            count = (2 * vcrp->vcr_nalloc);
        }
        if (count < 16) {
            count = 16;
        }
        mem = (void **) malloc(3 * count * sizeof(void*));
        if (!mem)
            return 0;

        for (i = 0; i < vcrp->base.vc_npatterns; i++) {
            mem[i] = vcrp->vcr_regex[i];
            mem[count + i] = vcrp->vcr_regex_extra[i];
            mem[(2 * count) + i] = (void *) vcrp->vcr_regex_pat[i];
        }

        if (vcrp->vcr_nalloc)
            free(vcrp->vcr_regex);
        vcrp->vcr_regex = (pcre **) mem;
        vcrp->vcr_regex_extra = (pcre_extra **) &mem[count];
        vcrp->vcr_regex_pat = (const char **) &mem[2 * count];
        vcrp->vcr_nalloc = count;
    }

    nres = vcrp->base.vc_npatterns;
    for (i = 0; i < npatterns; i++) {
        vcrp->vcr_regex[nres] =
            pcre_compile(patterns[i], 0,
                     &pcre_errptr, &pcre_erroffset, NULL);
        if (!vcrp->vcr_regex[nres]) {
            const char *spaces = "                ";
            fprintf(stderr, "%s\n", patterns[i]);
            while (pcre_erroffset > 16) {
                fprintf(stderr, "%s", spaces);
                pcre_erroffset -= 16;
            }
            if (pcre_erroffset > 0)
                fprintf(stderr,
                    "%s", &spaces[16 - pcre_erroffset]);
            fprintf(stderr, "^\nRegex error: %s\n", pcre_errptr);
            continue;
        }
        vcrp->vcr_regex_extra[nres] =
            pcre_study(vcrp->vcr_regex[nres], 0, &pcre_errptr);
        if (pcre_errptr) {
            fprintf(stderr, "Regex error: %s\n", pcre_errptr);
            pcre_free(vcrp->vcr_regex[nres]);
            continue;
        }
        vcrp->vcr_regex_pat[nres] = patterns[i];
        nres += 1;
    }

    if (nres == vcrp->base.vc_npatterns)
        return 0;

    vcrp->base.vc_npatterns_start += (nres - vcrp->base.vc_npatterns);
    vcrp->base.vc_npatterns = nres;
    return 1;
}

static void
vg_regex_context_clear_all_patterns(vg_context_t *vcp)
{
    vg_regex_context_t *vcrp = (vg_regex_context_t *) vcp;
    int i;
    for (i = 0; i < vcrp->base.vc_npatterns; i++) {
        if (vcrp->vcr_regex_extra[i])
            pcre_free(vcrp->vcr_regex_extra[i]);
        pcre_free(vcrp->vcr_regex[i]);
    }
    vcrp->base.vc_npatterns = 0;
    vcrp->base.vc_npatterns_start = 0;
    vcrp->base.vc_found = 0;
}

static void
vg_regex_context_free(vg_context_t *vcp)
{
    vg_regex_context_t *vcrp = (vg_regex_context_t *) vcp;
    vg_regex_context_clear_all_patterns(vcp);
    if (vcrp->vcr_nalloc)
        free(vcrp->vcr_regex);
    free(vcrp);
}

static int
vg_regex_test(vg_exec_context_t *vxcp)
{
    vg_regex_context_t *vcrp = (vg_regex_context_t *) vxcp->vxc_vc;

    unsigned char hash1[32], hash2[32];
    int i, zpfx, p, d, nres, re_vec[9];
    char b58[40];
    BIGNUM bnrem;
    BIGNUM *bn, *bndiv, *bnptmp;
    int res = 0;

    pcre *re;

    BN_init(&bnrem);

    /* Hash the hash and write the four byte check code */
    SHA256(vxcp->vxc_binres, 21, hash1);
    SHA256(hash1, sizeof(hash1), hash2);
    memcpy(&vxcp->vxc_binres[21], hash2, 4);

    bn = &vxcp->vxc_bntmp;
    bndiv = &vxcp->vxc_bntmp2;

    BN_bin2bn(vxcp->vxc_binres, 25, bn);

    /* Compute the complete encoded address */
    for (zpfx = 0; zpfx < 25 && vxcp->vxc_binres[zpfx] == 0; zpfx++);
    p = sizeof(b58) - 1;
    b58[p] = '\0';
    while (!BN_is_zero(bn)) {
        BN_div(bndiv, &bnrem, bn, &vxcp->vxc_bnbase, vxcp->vxc_bnctx);
        bnptmp = bn;
        bn = bndiv;
        bndiv = bnptmp;
        d = BN_get_word(&bnrem);
        b58[--p] = vg_b58_alphabet[d];
    }
    while (zpfx--) {
        b58[--p] = vg_b58_alphabet[0];
    }

    /*
     * Run the regular expressions on it
     * SLOW, runs in linear time with the number of REs
     */
restart_loop:
    nres = vcrp->base.vc_npatterns;
    if (!nres) {
        res = 2;
        goto out;
    }
    for (i = 0; i < nres; i++) {
        d = pcre_exec(vcrp->vcr_regex[i],
                  vcrp->vcr_regex_extra[i],
                  &b58[p], (sizeof(b58) - 1) - p, 0,
                  0,
                  re_vec, sizeof(re_vec)/sizeof(re_vec[0]));

        if (d <= 0) {
            if (d != PCRE_ERROR_NOMATCH) {
                fprintf(stderr, "PCRE error: %d\n", d);
                res = 2;
                goto out;
            }
            continue;
        }

        re = vcrp->vcr_regex[i];

        if (vg_exec_context_upgrade_lock(vxcp) &&
            ((i >= vcrp->base.vc_npatterns) ||
             (vcrp->vcr_regex[i] != re)))
            goto restart_loop;

        vg_exec_context_consolidate_key(vxcp);
        vcrp->base.vc_output_match(&vcrp->base, vxcp->vxc_key,
                       vcrp->vcr_regex_pat[i]);
        vcrp->base.vc_found++;

        if (vcrp->base.vc_only_one) {
            res = 2;
            goto out;
        }

        if (vcrp->base.vc_remove_on_match) {
            pcre_free(vcrp->vcr_regex[i]);
            if (vcrp->vcr_regex_extra[i])
                pcre_free(vcrp->vcr_regex_extra[i]);
            nres -= 1;
            vcrp->base.vc_npatterns = nres;
            if (!nres) {
                res = 2;
                goto out;
            }
            vcrp->vcr_regex[i] = vcrp->vcr_regex[nres];
            vcrp->vcr_regex_extra[i] =
                vcrp->vcr_regex_extra[nres];
            vcrp->vcr_regex_pat[i] = vcrp->vcr_regex_pat[nres];
            vcrp->base.vc_npatterns = nres;
            vcrp->base.vc_pattern_generation++;
        }
        res = 1;
    }
out:
    BN_clear_free(&bnrem);
    return res;
}

vg_context_t *
vg_regex_context_new(int addrtype, int privtype)
{
    vg_regex_context_t *vcrp;

    vcrp = (vg_regex_context_t *) malloc(sizeof(*vcrp));
    if (vcrp) {
        memset(vcrp, 0, sizeof(*vcrp));
        vcrp->base.vc_addrtype = addrtype;
        vcrp->base.vc_privtype = privtype;
        vcrp->base.vc_npatterns = 0;
        vcrp->base.vc_npatterns_start = 0;
        vcrp->base.vc_found = 0;
        vcrp->base.vc_chance = 0.0;
        vcrp->base.vc_free = vg_regex_context_free;
        vcrp->base.vc_add_patterns = vg_regex_context_add_patterns;
        vcrp->base.vc_clear_all_patterns =
            vg_regex_context_clear_all_patterns;
        vcrp->base.vc_test = vg_regex_test;
        vcrp->base.vc_hash160_sort = NULL;
        vcrp->vcr_regex = NULL;
        vcrp->vcr_nalloc = 0;
    }
    return &vcrp->base;
}

// patterns.c

int
VanityGen(int addrtype, char *prefix, char *pubKey, char *privKey)
{
    int scriptaddrtype = 0;
    int privtype = 128;
    int pubkeytype;
    enum vg_format format = VCF_PUBKEY;
    int regex = 0;
    int caseinsensitive = 0;
    int verbose = 0;
    int simulate = 0;
    int remove_on_match = 1;
    int only_one = 0;
    int prompt_password = 0;
    char pwbuf[128];
    const char *result_file = NULL;
    const char *key_password = NULL;
    char **patterns;
    int npatterns = 0;
    int nthreads = 0;
    vg_context_t *vcp = NULL;
    EC_POINT *pubkey_base = NULL;

    int npattfp = 0;

    privtype = 128 + addrtype;
    scriptaddrtype = addrtype;

#if OPENSSL_VERSION_NUMBER < 0x10000000L
    /* Complain about older versions of OpenSSL */
    if (verbose > 0) {
        fprintf(stderr,
            "WARNING: Built with " OPENSSL_VERSION_TEXT "\n"
            "WARNING: Use OpenSSL 1.0.0d+ for best performance\n");
    }
#endif


    pubkeytype = addrtype;
    if (format == VCF_SCRIPT)
    {
        if (scriptaddrtype == -1)
        {
            fprintf(stderr,
                "Address type incompatible with script format\n");
            return 1;
        }
        addrtype = scriptaddrtype;
    }


    if (regex) {
        vcp = vg_regex_context_new(addrtype, privtype);

    } else {
        vcp = vg_prefix_context_new(addrtype, privtype,
                        caseinsensitive);
    }

    vcp->vc_verbose = verbose;
    vcp->vc_result_file = result_file;
    vcp->vc_remove_on_match = remove_on_match;
    vcp->vc_only_one = only_one;
    vcp->vc_format = format;
    vcp->vc_pubkeytype = pubkeytype;
    vcp->vc_pubkey_base = pubkey_base;

    vcp->vc_output_match = vg_output_match_console;
    vcp->vc_output_timing = vg_output_timing_console;

    if (!npattfp) {

        patterns = &prefix;
        npatterns = 1;

        if (!vg_context_add_patterns(vcp,
                         (const char ** const) patterns,
                         npatterns))
        return 1;
    }

    if (!vcp->vc_npatterns) {
        fprintf(stderr, "No patterns to search\n");
        return 1;
    }

    if (prompt_password) {
        if (!vg_read_password(pwbuf, sizeof(pwbuf)))
            return 1;
        key_password = pwbuf;
    }
    vcp->vc_key_protect_pass = key_password;
    if (key_password) {
        if (!vg_check_password_complexity(key_password, verbose))
            fprintf(stderr,
                "WARNING: Protecting private keys with "
                "weak password\n");
    }

    if ((verbose > 0) && regex && (vcp->vc_npatterns > 1))
        fprintf(stderr,
            "Regular expressions: %ld\n", vcp->vc_npatterns);

    if (simulate)
        return 0;

    if (!start_threads(vcp, nthreads))
        return 1;

    strcpy(pubKey, VG_PUB_KEY_BUF);
    strcpy(privKey, VG_PRV_KEY_BUF);
    return 0;
}



void
usage(const char *name)
{
	fprintf(stderr,
"Vanitygen %s (" OPENSSL_VERSION_TEXT ")\n"
"Usage: %s [-vqnrik1NT] [-t <threads>] [-f <filename>|-] [<pattern>...]\n"
"Generates a bitcoin receiving address matching <pattern>, and outputs the\n"
"address and associated private key.  The private key may be stored in a safe\n"
"location or imported into a bitcoin client to spend any balance received on\n"
"the address.\n"
"By default, <pattern> is interpreted as an exact prefix.\n"
"\n"
"Options:\n"
"-v            Verbose output\n"
"-q            Quiet output\n"
"-n            Simulate\n"
"-r            Use regular expression match instead of prefix\n"
"              (Feasibility of expression is not checked)\n"
"-i            Case-insensitive prefix search\n"
"-k            Keep pattern and continue search after finding a match\n"
"-1            Stop after first match\n"
"-N            Generate namecoin address\n"
"-T            Generate bitcoin testnet address\n"
"-X <version>  Generate address with the given version\n"
"-F <format>   Generate address with the given format (pubkey or script)\n"
"-P <pubkey>   Specify base public key for piecewise key generation\n"
"-e            Encrypt private keys, prompt for password\n"
"-E <password> Encrypt private keys with <password> (UNSAFE)\n"
"-t <threads>  Set number of worker threads (Default: number of CPUs)\n"
"-f <file>     File containing list of patterns, one per line\n"
"              (Use \"-\" as the file name for stdin)\n"
"-o <file>     Write pattern matches to <file>\n"
"-s <file>     Seed random number generator from <file>\n",
version, name);
}

#define MAX_FILE 4

#ifdef VANITY_MAIN

int
main(int argc, char **argv)
{
	int addrtype = 0;
	int scriptaddrtype = 5;
	int privtype = 128;
	int pubkeytype;
	enum vg_format format = VCF_PUBKEY;
	int regex = 0;
	int caseinsensitive = 0;
	int verbose = 1;
	int simulate = 0;
	int remove_on_match = 1;
	int only_one = 0;
	int prompt_password = 0;
	int opt;
	char *seedfile = NULL;
	char pwbuf[128];
	const char *result_file = NULL;
	const char *key_password = NULL;
	char **patterns;
	int npatterns = 0;
	int nthreads = 0;
	vg_context_t *vcp = NULL;
	EC_POINT *pubkey_base = NULL;

	FILE *pattfp[MAX_FILE], *fp;
	int pattfpi[MAX_FILE];
	int npattfp = 0;
	int pattstdin = 0;

	int i;

	while ((opt = getopt(argc, argv, "vqnrik1eE:P:NTX:F:t:h?f:o:s:")) != -1) {
		switch (opt) {
		case 'v':
			verbose = 2;
			break;
		case 'q':
			verbose = 0;
			break;
		case 'n':
			simulate = 1;
			break;
		case 'r':
			regex = 1;
			break;
		case 'i':
			caseinsensitive = 1;
			break;
		case 'k':
			remove_on_match = 0;
			break;
		case '1':
			only_one = 1;
			break;
		case 'N':
			addrtype = 52;
			privtype = 180;
			scriptaddrtype = -1;
			break;
		case 'T':
			addrtype = 111;
			privtype = 239;
			scriptaddrtype = 196;
			break;
		case 'X':
			addrtype = atoi(optarg);
			privtype = 128 + addrtype;
			scriptaddrtype = addrtype;
			break;
		case 'F':
			if (!strcmp(optarg, "script"))
				format = VCF_SCRIPT;
			else
			if (strcmp(optarg, "pubkey")) {
				fprintf(stderr,
					"Invalid format '%s'\n", optarg);
				return 1;
			}
			break;
		case 'P': {
			if (pubkey_base != NULL) {
				fprintf(stderr,
					"Multiple base pubkeys specified\n");
				return 1;
			}
			EC_KEY *pkey = vg_exec_context_new_key();
			pubkey_base = EC_POINT_hex2point(
				EC_KEY_get0_group(pkey),
				optarg, NULL, NULL);
			EC_KEY_free(pkey);
			if (pubkey_base == NULL) {
				fprintf(stderr,
					"Invalid base pubkey\n");
				return 1;
			}
			break;
		}
			
		case 'e':
			prompt_password = 1;
			break;
		case 'E':
			key_password = optarg;
			break;
		case 't':
			nthreads = atoi(optarg);
			if (nthreads == 0) {
				fprintf(stderr,
					"Invalid thread count '%s'\n", optarg);
				return 1;
			}
			break;
		case 'f':
			if (npattfp >= MAX_FILE) {
				fprintf(stderr,
					"Too many input files specified\n");
				return 1;
			}
			if (!strcmp(optarg, "-")) {
				if (pattstdin) {
					fprintf(stderr, "ERROR: stdin "
						"specified multiple times\n");
					return 1;
				}
				fp = stdin;
			} else {
				fp = fopen(optarg, "r");
				if (!fp) {
					fprintf(stderr,
						"Could not open %s: %s\n",
						optarg, strerror(errno));
					return 1;
				}
			}
			pattfp[npattfp] = fp;
			pattfpi[npattfp] = caseinsensitive;
			npattfp++;
			break;
		case 'o':
			if (result_file) {
				fprintf(stderr,
					"Multiple output files specified\n");
				return 1;
			}
			result_file = optarg;
			break;
		case 's':
			if (seedfile != NULL) {
				fprintf(stderr,
					"Multiple RNG seeds specified\n");
				return 1;
			}
			seedfile = optarg;
			break;
        default:
			usage(argv[0]);
			return 1;
		}
	}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
	/* Complain about older versions of OpenSSL */
	if (verbose > 0) {
		fprintf(stderr,
			"WARNING: Built with " OPENSSL_VERSION_TEXT "\n"
			"WARNING: Use OpenSSL 1.0.0d+ for best performance\n");
	}
#endif

	if (caseinsensitive && regex)
		fprintf(stderr,
			"WARNING: case insensitive mode incompatible with "
			"regular expressions\n");

	pubkeytype = addrtype;
	if (format == VCF_SCRIPT)
	{
		if (scriptaddrtype == -1)
		{
			fprintf(stderr,
				"Address type incompatible with script format\n");
			return 1;
		}
		addrtype = scriptaddrtype;
	}

	if (seedfile) {
		opt = -1;
#if !defined(WIN32)
		{	struct stat st;
			if (!stat(seedfile, &st) &&
			    (st.st_mode & (S_IFBLK|S_IFCHR))) {
				opt = 32;
		} }
#endif
		opt = RAND_load_file(seedfile, opt);
		if (!opt) {
			fprintf(stderr, "Could not load RNG seed %s\n", optarg);
			return 1;
		}
		if (verbose > 0) {
			fprintf(stderr,
				"Read %d bytes from RNG seed file\n", opt);
		}
	}

	if (regex) {
		vcp = vg_regex_context_new(addrtype, privtype);

	} else {
		vcp = vg_prefix_context_new(addrtype, privtype,
					    caseinsensitive);
	}

	vcp->vc_verbose = verbose;
	vcp->vc_result_file = result_file;
	vcp->vc_remove_on_match = remove_on_match;
	vcp->vc_only_one = only_one;
	vcp->vc_format = format;
	vcp->vc_pubkeytype = pubkeytype;
	vcp->vc_pubkey_base = pubkey_base;

	vcp->vc_output_match = vg_output_match_console;
	vcp->vc_output_timing = vg_output_timing_console;

	if (!npattfp) {
		if (optind >= argc) {
			usage(argv[0]);
			return 1;
		}
		patterns = &argv[optind];
		npatterns = argc - optind;

		if (!vg_context_add_patterns(vcp,
					     (const char ** const) patterns,
					     npatterns))
		return 1;
	}

	for (i = 0; i < npattfp; i++) {
		fp = pattfp[i];
		if (!vg_read_file(fp, &patterns, &npatterns)) {
			fprintf(stderr, "Failed to load pattern file\n");
			return 1;
		}
		if (fp != stdin)
			fclose(fp);

		if (!regex)
			vg_prefix_context_set_case_insensitive(vcp, pattfpi[i]);

		if (!vg_context_add_patterns(vcp,
					     (const char ** const) patterns,
					     npatterns))
		return 1;
	}

	if (!vcp->vc_npatterns) {
		fprintf(stderr, "No patterns to search\n");
		return 1;
	}

	if (prompt_password) {
		if (!vg_read_password(pwbuf, sizeof(pwbuf)))
			return 1;
		key_password = pwbuf;
	}
	vcp->vc_key_protect_pass = key_password;
	if (key_password) {
		if (!vg_check_password_complexity(key_password, verbose))
			fprintf(stderr,
				"WARNING: Protecting private keys with "
				"weak password\n");
	}

	if ((verbose > 0) && regex && (vcp->vc_npatterns > 1))
		fprintf(stderr,
			"Regular expressions: %ld\n", vcp->vc_npatterns);

	if (simulate)
		return 0;

	if (!start_threads(vcp, nthreads))
		return 1;
	return 0;
}
#endif // VANITY_MAIN
