#ifndef TYPES_HPP
#define TYPES_HPP

#include <bls.hpp>
#include <util.hpp>
#include <utility>
extern "C" {
    #include "relic.h"
    #include "rsa_util.h"
}
using msg_t = std::vector<uint8_t>;
using pkv_t = std::vector<uint8_t>;
using sigv_t = std::vector<uint8_t>;
using sk_t = bls::PrivateKey;
using skv_t = std::vector<uint8_t>;
using pk_t = bls::G1Element;
using signature_t = bls::G2Element;
using aggsig_t = bls::G2Element;
using aggsigv_t = std::vector<uint8_t>;
using cert_t = std::vector<uint8_t>;
using hash_t = std::size_t;
using timestamp_t = int64_t;
using reveal_t = uint64_t;
constexpr int RSA_KEY_LEN = BN_PRECI;


#endif

