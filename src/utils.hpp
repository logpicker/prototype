#ifndef LPP_UTILS_HPP
#define LPP_UTILS_HPP

#include <vector>
#include "log.hpp"
#include "types.hpp"
#include "rpc/msgpack.hpp"
#include "rpc/msgpack/sbuffer.h"
#include "logpicker_t.hpp"
#include <random>
#include <limits>

inline std::vector<Log> make_logs(int count) {
    std::vector<Log> logs;
    logs.reserve(count);
    for(int i=0; i < count; i++) {
        logs.emplace_back(i, "127.0.0.1", vector<uint8_t>(32, i));
    }
    return logs;
}

template<typename T> msg_t message_contents(const T& req) {
    clmdep_msgpack::sbuffer buf;
    clmdep_msgpack::pack(buf, req);
    const char* data = buf.data();
    return {data, data+buf.size()};
}

inline std::vector<uint8_t> random_data() {
    // Seed with a real random value, if available
    std::random_device r;

    // Choose a random mean between 1 and 6
    std::default_random_engine e1(r());
    std::uniform_int_distribution<uint8_t> uniform_dist(std::numeric_limits<uint8_t>::min(), std::numeric_limits<uint8_t>::max());
    std::vector<uint8_t> data;
    const int items = 8;
    data.reserve(items);
    for(int i = 0; i < items; i++) {
        data.emplace_back(uniform_dist(e1));
    }
    return data;
}

inline logpicker_t make_instance(const Log& log) {
    const int base_port = 8080;
    return logpicker_t(log.get_id(),log.get_hostname(), base_port+log.get_id(), log.getPublicKeyVec(), log.get_rsa_pk());
}

inline log_map_t read_log_pool(const std::string& config_filename) {
    log_map_t lp;
    int i = 0;
    while(true) {
        auto log = Log::read_log(config_filename, i);
        if(log) {
            lp.emplace(i, make_instance(log.value()));
            i++;
        } else {
            break;
        }
    }
    return lp;
}
inline int calculate_winner(const std::vector<reveal_t>& reveals) {
    int sum = 0;
    for(auto rev : reveals) {
        sum += rev;
    }
    return sum % reveals.size();
}
#endif
