#include "rsa_util.h"
#include "relic.h"

typedef uint32_t hdr_t;
static const int HEADER_SIZE = sizeof(uint32_t);

static int bn_size_bin_safe(const bn_t a)
{
    /*
     * Relics bn_size_bin returns unexpected results for bn_t objects with
     * value 0. Therefor we check for value 0 and return the expected result.
     */
    if (bn_is_zero(a) == 1) {
        return 0;
    }

    return bn_size_bin(a);
}

int rsa_key_size_bin(const rsa_t key)
{
    /* each rsa_t references 8 bn_t objects */
    const int N = 8;

    /* total_size (size_t) || size_i (size_t) || data_i (uint8_t[size_i] */
    int size = (N + 1) * HEADER_SIZE;


    size += bn_size_bin_safe(key->d);
    size += bn_size_bin_safe(key->e);
    size += bn_size_bin_safe(key->crt->n);
    size += bn_size_bin_safe(key->crt->p);
    size += bn_size_bin_safe(key->crt->q);
    size += bn_size_bin_safe(key->crt->dp);
    size += bn_size_bin_safe(key->crt->dq);
    size += bn_size_bin_safe(key->crt->qi);


    return size;
}


static void write_and_inc_ptr(uint8_t **bin, const bn_t a)
{
    const hdr_t size = bn_size_bin_safe(a);
    memcpy(*bin, &size, HEADER_SIZE);
    *bin += HEADER_SIZE;


    if (size) {
        bn_write_bin(*bin, size, a);
        *bin += size;
    }
}


void rsa_key_write_bin(uint8_t *bin, const rsa_t key)
{
    const hdr_t size = rsa_key_size_bin(key);
    memcpy(bin, &size, HEADER_SIZE);
    bin += HEADER_SIZE;

    write_and_inc_ptr(&bin, key->d);
    write_and_inc_ptr(&bin, key->e);
    write_and_inc_ptr(&bin, key->crt->n);
    write_and_inc_ptr(&bin, key->crt->p);
    write_and_inc_ptr(&bin, key->crt->q);
    write_and_inc_ptr(&bin, key->crt->dp);
    write_and_inc_ptr(&bin, key->crt->dq);
    write_and_inc_ptr(&bin, key->crt->qi);
}

static void read_and_inc_ptr(bn_t a, const uint8_t **bin)
{
    hdr_t size = 0;
    memcpy(&size, *bin, HEADER_SIZE);
    *bin += HEADER_SIZE;

    if (size) {
        bn_read_bin(a, *bin, size);
        *bin += size;
    } else {
        bn_zero(a);
    }
}

void rsa_key_read_bin(rsa_t key, const uint8_t *bin)
{
    hdr_t size = 0;
    memcpy(&size, bin, HEADER_SIZE);
    bin += HEADER_SIZE;

    read_and_inc_ptr(key->d, &bin);
    read_and_inc_ptr(key->e, &bin);
    read_and_inc_ptr(key->crt->n, &bin);
    read_and_inc_ptr(key->crt->p, &bin);
    read_and_inc_ptr(key->crt->q, &bin);
    read_and_inc_ptr(key->crt->dp, &bin);
    read_and_inc_ptr(key->crt->dq, &bin);
    read_and_inc_ptr(key->crt->qi, &bin);
}
