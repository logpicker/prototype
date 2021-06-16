#include "types.hpp"
#include <iostream>
#include <util.hpp>

#include <vector>
extern "C" {
#include "relic.h"
#include "rsa_util.h"
}
#include "utils.hpp"
#include "logpicker_messages.hpp"
#include "crypto.hpp"

void massert(bool v) {
    if(!v) {
        throw std::logic_error("assert failed");
    }
}

int main() {
    core_init();
    const int RSA_KEY_LEN = BN_PRECI;
    rsa_t prv;
    rsa_t pub;

    rsa_new(prv);
    rsa_new(pub);

    auto r = cp_rsa_gen(pub, prv, RSA_KEY_LEN);
    if(r == RLC_OK) {
        std::cout << "RLC OK for keygen\n";
    } else {
        std::cout << "RLC NOK for keygen\n";

    }
    int pub_len = rsa_key_size_bin(pub);
    uint8_t pub_bin[pub_len];
    int prv_len = rsa_key_size_bin(prv);
    uint8_t prv_bin[prv_len];
    rsa_key_write_bin(pub_bin, pub);
    rsa_key_write_bin(prv_bin, prv);
    std::string pub_str = bls::Util::HexStr(pub_bin, pub_len);
    std::string prv_str = bls::Util::HexStr(prv_bin, prv_len);
    auto pub_bs = bls::Util::HexToBytes(pub_str);
    for(int i = 0; i < pub_len; i++) {
        auto lhs = pub_bin[i];
        auto rhs = pub_bs[i];
        if(lhs != rhs) {
            std::cout << "Diff at idx: " << i << "\n";
        }
    }
    crypto::rsa_pub_key_t pubk{pub_str};
    auto pk = pubk.key();
    massert(RLC_EQ == bn_cmp(pub->d, pk->d));
    massert(RLC_EQ == bn_cmp(pub->e, pk->e));
    massert(RLC_EQ == bn_cmp(pub->crt->n, pk->crt->n));
    massert(RLC_EQ == bn_cmp(pub->crt->p, pk->crt->p));
    massert(RLC_EQ == bn_cmp(pub->crt->q, pk->crt->q));
    massert(RLC_EQ == bn_cmp(pub->crt->dp, pk->crt->dp));
    massert(RLC_EQ == bn_cmp(pub->crt->dq, pk->crt->dq));
    massert(RLC_EQ == bn_cmp(pub->crt->qi, pk->crt->qi));
    crypto::rsa_priv_key_t prvk{prv_str};
    auto pvk = prvk.key();
    massert(RLC_EQ == bn_cmp(prv->d, pvk->d));
    massert(RLC_EQ == bn_cmp(prv->e, pvk->e));
    massert(RLC_EQ == bn_cmp(prv->crt->n, pvk->crt->n));
    massert(RLC_EQ == bn_cmp(prv->crt->p, pvk->crt->p));
    massert(RLC_EQ == bn_cmp(prv->crt->q, pvk->crt->q));
    massert(RLC_EQ == bn_cmp(prv->crt->dp, pvk->crt->dp));
    massert(RLC_EQ == bn_cmp(prv->crt->dq, pvk->crt->dq));
    massert(RLC_EQ == bn_cmp(prv->crt->qi, pvk->crt->qi));
    session_id_t m(1, 5);
    msg_t mv = message_contents(m);

    auto sig = prvk.sign_rsa(mv);
    auto succ = pubk.verify_rsa(sig, mv);
    std::cout << "Result: " << (((bool) succ) ? "YES" : "NO") << "\n";

}