#ifndef LPP_LOG_HPP
#define LPP_LOG_HPP

#include "crypto.hpp"
#include <utility>
#include <optional>
#include <boost/property_tree/ptree.hpp>
extern "C" {
#include "relic.h"
}
namespace pt = boost::property_tree;

class Log {

public:
    explicit Log(int id_, std::string hostname_, vector<uint8_t> seed);
    explicit Log(int id_, std::string hostname_, skv_t skv, pkv_t pkv, std::string rsa_pk_, std::string rsa_sk_);

    static std::optional<Log> read_log(const std::string& filename, int id);
    static Log read_leader(const std::string& filename);
     pt::ptree to_ptree() const;
     int get_id() const;

     pk_t getPublicKey() const;
     pkv_t getPublicKeyVec() const;
     signature_t sign(const msg_t& msg) const;
     signature_t sign(msg_t&& msg) const;
     sigv_t sign_rsa(const msg_t& msg);
     sigv_t sign_rsa(msg_t&& msg);
     std::string get_rsa_pk() const;
     std::string get_hostname() const;

private:
    int id;
    sk_t sk;
    pk_t pk;
    pkv_t pkv;
    rsa_t rsa_pk;
    rsa_t rsa_sk;
    std::string hostname;
};
#endif
