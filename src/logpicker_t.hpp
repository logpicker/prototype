#ifndef LPP_LOGPICKER_T_HPP
#define LPP_LOGPICKER_T_HPP

#include <utility>
#include <string>
#include <vector>
#include <unordered_map>

#include "types.hpp"

#include "rpc/msgpack.hpp"

struct logpicker_t {

    logpicker_t(int id_, std::string hostname_, int port_, pkv_t pk, std::string rsa_pk_) : id(id_), port(port_), pkv(std::move(pk)), rsa_pk(std::move(rsa_pk_)), hostname(std::move(hostname_)) {}

    logpicker_t() = default;
    logpicker_t(logpicker_t&&) = default;
    logpicker_t(const logpicker_t&) = default;
    logpicker_t& operator=(const logpicker_t&) = default;

     int get_id() const { return this->id; }

     std::string get_hostname() const { return this->hostname; }

     int get_port() const { return this->port; }

     pkv_t get_pkv() const { return this->pkv; }
    std::string get_rsa_pk() const { return this->rsa_pk; }
    int id;
    int port;
    pkv_t pkv;
    std::string rsa_pk;
    std::string hostname;

    MSGPACK_DEFINE_ARRAY(id, port, pkv, rsa_pk, hostname)
};

using log_pool_t = std::vector<int>;
using log_map_t = std::unordered_map<int, logpicker_t>;

#endif
