#include "log.hpp"
#include "printfn.hpp"
#include "error_out.hpp"
#include <utility>
#include <boost/property_tree/xml_parser.hpp>
#include <string>
extern "C" {
#include "rsa_util.h"
}
Log::Log(int id_, std::string hostname_, vector<uint8_t> seed) : id(id_), sk(crypto::generate_secret_key(std::move(seed))), pk(crypto::secret_to_public_key(sk)), pkv(crypto::secret_to_public_key_vec(sk)), hostname(std::move(hostname_)) {
    rsa_new(this->rsa_pk);
    rsa_new(this->rsa_sk);
    auto r = cp_rsa_gen(this->rsa_pk, this->rsa_sk, RSA_KEY_LEN);
    if(r != RLC_OK) {
        throw std::logic_error("RLC IS FUCKED");
    }
}

std::optional<Log> Log::read_log(const std::string& filename, int id) {
    pt::ptree tree;
    pt::read_xml(filename, tree);
    for(pt::ptree::value_type &v : tree.get_child("lpp.logs")) {
        const std::string& key = v.first;
        lpp::printfn("Read key: {}\n", key);
        const pt::ptree& subtree = v.second;
        if(subtree.empty()) {
            lpp::error_out("Subtree of key {} is empty!", key);
        }
        auto lid = subtree.get<int>("id");
        if(lid == id) {
            auto hostname = subtree.get<std::string>("host");
            auto sks = subtree.get<std::string>("sk");
            auto skb = bls::Util::HexToBytes(sks);
            auto pks = subtree.get<std::string>("pk");
            auto pkb = bls::Util::HexToBytes(sks);
            auto rsa_pk = subtree.get<std::string>("rsa_pk");
            auto rsa_sk = subtree.get<std::string>("rsa_sk");
            lpp::printfn("Constructing Log with id {} on host: {}\nSK: {}\nPK: {}, RSA PK: {}, RSA SK: {}\n", lid, hostname, sks, pks, rsa_pk, rsa_sk);
            return Log{lid, hostname, skb, pkb, rsa_pk, rsa_sk};
        }
    }
    //lpp::error_out("ERROR");
    return {};
}

int Log::get_id() const { return this->id; }

pk_t Log::getPublicKey() const { return this->pk; }

pkv_t Log::getPublicKeyVec() const { return this->pkv; }

sigv_t Log::sign_rsa(const msg_t &msg) {
    uint8_t out[RLC_BN_BITS / 8 + 1];
    int ol = RLC_BN_BITS / 8 + 1;
    auto ret = cp_rsa_sig(out, &ol, (uint8_t*) msg.data(), msg.size(), 0, this->rsa_sk);
    if(ret != RLC_OK) {
        throw std::logic_error("RLC IS FUCKED");
    }
    sigv_t sig;
    sig.reserve(ol);
    sig.assign(out, out+ol);
    return sig;
}
std::string Log::get_rsa_pk() const {
    int pub_len = rsa_key_size_bin(this->rsa_pk);
    uint8_t pub_bin[pub_len];
    rsa_key_write_bin(pub_bin, this->rsa_pk);
    return bls::Util::HexStr(pub_bin, pub_len);
}

sigv_t Log::sign_rsa(msg_t &&msg) {
    uint8_t out[RLC_BN_BITS / 8 + 1];
    int ol = RLC_BN_BITS / 8 + 1;
    auto ret = cp_rsa_sig(out, &ol, msg.data(), msg.size(), 0, this->rsa_sk);
    if(ret != RLC_OK) {
        throw std::logic_error("RLC IS FUCKED");
    }
    sigv_t sig;
    sig.reserve(ol);
    sig.assign(out, out+ol);
    return sig;
}

signature_t Log::sign(const msg_t &msg) const {
    return crypto::sign(this->sk, msg);
}

signature_t Log::sign(msg_t &&msg) const {
    return crypto::sign(this->sk, msg);
}
Log::Log(int id_, std::string hostname_, skv_t skv, pkv_t pkv_, std::string rsa_pk_, std::string rsa_sk_) : id(id_), sk(bls::PrivateKey::FromByteVector(std::move(skv))), pk(crypto::secret_to_public_key(sk)), pkv(pk.Serialize()), hostname(std::move(hostname_)) {
    rsa_new(this->rsa_pk);
    rsa_new(this->rsa_sk);
    auto bs_pk = bls::Util::HexToBytes(std::move(rsa_pk_));
    rsa_key_read_bin(this->rsa_pk, bs_pk.data());
    auto bs_sk = bls::Util::HexToBytes(std::move(rsa_sk_));
    rsa_key_read_bin(this->rsa_sk, bs_sk.data());
}

pt::ptree Log::to_ptree() const {
    pt::ptree tree;
    std::string sks = bls::Util::HexStr(this->sk.Serialize());
    std::string pks = bls::Util::HexStr(this->pkv);
    tree.put("id", this->get_id());
    tree.put("host", this->get_hostname());
    tree.put("sk", sks);
    tree.put("pk", pks);
    int pub_len = rsa_key_size_bin(this->rsa_pk);
    uint8_t pub_bin[pub_len];
    rsa_key_write_bin(pub_bin, this->rsa_pk);
    std::string pub_str = bls::Util::HexStr(pub_bin, pub_len);

    int prv_len = rsa_key_size_bin(this->rsa_sk);
    uint8_t prv_bin[prv_len];
    rsa_key_write_bin(prv_bin, this->rsa_sk);
    std::string prv_str = bls::Util::HexStr(prv_bin, prv_len);
    tree.put("rsa_pk", pub_str);
    tree.put("rsa_sk", prv_str);
    return tree;
}

Log Log::read_leader(const std::string &filename) {
    pt::ptree tree;
    pt::read_xml(filename, tree);
    auto lid = tree.get<int>("lpp.leader.id");
    auto hostname = tree.get<std::string>("lpp.leader.host");
    auto sks = tree.get<std::string>("lpp.leader.sk");
    auto skb = bls::Util::HexToBytes(sks);
    auto pks = tree.get<std::string>("lpp.leader.pk");
    auto pkb = bls::Util::HexToBytes(sks);
    auto rsa_pk = tree.get<std::string>("lpp.leader.rsa_pk");
    auto rsa_sk = tree.get<std::string>("lpp.leader.rsa_sk");
    lpp::printfn("Constructing Leader with id {} on host: {}\nSK: {}\nPK: {}, RSA PK: {}, RSA SK: {}", lid, hostname, sks, pks, rsa_pk, rsa_sk);
    return Log{lid, hostname, skb, pkb, rsa_pk, rsa_sk};
}

std::string Log::get_hostname() const {
    return this->hostname;
}
