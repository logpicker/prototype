#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include "types.hpp"

namespace crypto {
  sk_t generate_secret_key(std::vector<uint8_t> seed);

  pk_t secret_to_public_key(const sk_t& sk);

  pkv_t secret_to_public_key_vec(const sk_t& sk);

  signature_t sign(const sk_t& sk, const msg_t& msg);
  signature_t sign(const sk_t& sk, msg_t&& msg);

  aggsig_t aggregate(const std::vector<signature_t>& sigs);

  aggsigv_t aggregate(const std::vector<sigv_t>& sigs);

  bool verify_aggsig(const std::vector<pk_t>& pks, const std::vector<msg_t>& msgs, const aggsig_t& aggsig);

  bool verify_aggsig(const std::vector<pkv_t>& pks, const std::vector<msg_t>& msgs, const aggsigv_t& aggsig);

  bool verify(const pkv_t& pk, const msg_t& msg, const sigv_t& sig);
    class rsa_pub_key_t {
    public:
        rsa_pub_key_t(std::string key_str);

        bool verify_rsa(sigv_t sig, msg_t message);
        rsa_t& key();

        ~rsa_pub_key_t();

    private:
        rsa_t key_;
    };
    class rsa_priv_key_t {
    public:
        rsa_priv_key_t(std::string key_str);

        sigv_t sign_rsa(msg_t message);

        rsa_t& key();

        ~rsa_priv_key_t();

    private:
        rsa_t key_;
    };

}

#endif

