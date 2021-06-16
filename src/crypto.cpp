#include "crypto.hpp"


sk_t crypto::generate_secret_key(std::vector<uint8_t> seed) {
return bls::BasicSchemeMPL::KeyGen(std::move(seed));
}

pk_t crypto::secret_to_public_key(const sk_t& sk) {
    return bls::BasicSchemeMPL::SkToG1(sk);
}

pkv_t crypto::secret_to_public_key_vec(const sk_t& sk) {
    return bls::BasicSchemeMPL::SkToPk(sk);
}

signature_t crypto::sign(const sk_t& sk, const msg_t& msg) {
    return bls::BasicSchemeMPL::Sign(sk, msg);
}

signature_t crypto::sign(const sk_t& sk, msg_t&& msg) {
    return bls::BasicSchemeMPL::Sign(sk, msg);
}

aggsig_t crypto::aggregate(const std::vector<signature_t>& sigs) {
    return bls::BasicSchemeMPL::Aggregate(sigs);
}

aggsigv_t crypto::aggregate(const std::vector<sigv_t>& sigs) {
    return bls::BasicSchemeMPL::Aggregate(sigs);
}

bool crypto::verify_aggsig(const std::vector<pk_t>& pks, const std::vector<msg_t>& msgs, const aggsig_t& aggsig) {
    return bls::BasicSchemeMPL::AggregateVerify(pks, msgs, aggsig);
}

bool crypto::verify_aggsig(const std::vector<pkv_t>& pks, const std::vector<msg_t>& msgs, const aggsigv_t& aggsig) {
    return bls::BasicSchemeMPL::AggregateVerify(pks, msgs, aggsig);
}

bool crypto::verify(const pkv_t& pk, const msg_t& msg, const sigv_t& sig) {
    //return true;
    return bls::BasicSchemeMPL::Verify(pk, msg, sig);
}

crypto::rsa_pub_key_t::rsa_pub_key_t(std::string key_str) : key_() {
    rsa_new(this->key_);
    auto bs = bls::Util::HexToBytes(std::move(key_str));
    rsa_key_read_bin(this->key_, bs.data());
}

bool crypto::rsa_pub_key_t::verify_rsa(sigv_t sig, msg_t message) {
    auto ret = cp_rsa_ver(sig.data(),
                          sig.size(), message.data(), message.size(), 0, this->key_);
    return ret;
}

rsa_t &crypto::rsa_pub_key_t::key() {
    return this->key_;
}

crypto::rsa_pub_key_t::~rsa_pub_key_t() {
    rsa_free(this->key_);
}

crypto::rsa_priv_key_t::rsa_priv_key_t(std::string key_str) : key_() {
    rsa_new(this->key_);
    auto bs = bls::Util::HexToBytes(std::move(key_str));
    rsa_key_read_bin(this->key_, bs.data());
}

sigv_t crypto::rsa_priv_key_t::sign_rsa(msg_t message) {
    uint8_t out[RLC_BN_BITS / 8 + 1];
    int ol = RLC_BN_BITS / 8 + 1;
    auto ret = cp_rsa_sig(out, &ol, message.data(), message.size(), 0, this->key_);
    if(ret != RLC_OK) {
        throw std::logic_error("RLC IS FUCKED");
    }
    sigv_t sig;
    sig.reserve(ol);
    sig.assign(out, out+ol);
    return sig;
}

rsa_t &crypto::rsa_priv_key_t::key() {
    return this->key_;
}

crypto::rsa_priv_key_t::~rsa_priv_key_t() {
    rsa_free(this->key_);
}
