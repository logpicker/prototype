#include "assert.h"

#include "rsa_util.h"
#include "relic.h"

int test_setup()
{
    return core_init();
}


int test_rsa_key_read_write_bin(rsa_t key)
{

    int len = rsa_key_size_bin(key);
    uint8_t bin[len];

    rsa_key_write_bin(bin, key);

    rsa_t copy;
    rsa_new(copy);

    rsa_key_read_bin(copy, bin);

    assert(len == rsa_key_size_bin(copy));

    assert(RLC_EQ == bn_cmp(key->d, copy->d));
    assert(RLC_EQ == bn_cmp(key->e, copy->e));
    assert(RLC_EQ == bn_cmp(key->crt->n, copy->crt->n));
    assert(RLC_EQ == bn_cmp(key->crt->p, copy->crt->p));
    assert(RLC_EQ == bn_cmp(key->crt->q, copy->crt->q));
    assert(RLC_EQ == bn_cmp(key->crt->dp, copy->crt->dp));
    assert(RLC_EQ == bn_cmp(key->crt->dq, copy->crt->dq));
    assert(RLC_EQ == bn_cmp(key->crt->qi, copy->crt->qi));

    return RLC_OK;
}



void test_rsa_key_pair_read_write_bin()
{
    const int RSA_KEY_LEN = BN_PRECI;
    rsa_t prv;
    rsa_t pub;

    rsa_new(prv);
    rsa_new(pub);

    cp_rsa_gen(pub, prv, RSA_KEY_LEN);

    assert(RLC_OK == test_rsa_key_read_write_bin(pub));
    assert(RLC_OK == test_rsa_key_read_write_bin(prv));

    rsa_free(prv);
    rsa_free(pub);
}





int main()
{
    assert(RLC_OK == test_setup());


    test_rsa_key_pair_read_write_bin();


    printf("passed\n");

    return 0;
}
