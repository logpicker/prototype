#ifndef LPP_LEADER_H
#define LPP_LEADER_H

#include <unordered_map>
#include <boost/asio.hpp>
#include <mutex>
#include <boost/asio/io_context.hpp>
#include "leader_instance.h"

class leader_t {
public:
    leader_t(boost::asio::io_context& ios_, Log l, const log_map_t& log_pool_);
    void run(size_t concurrency_level);
void start_run(const logpicker_request_t& req);
void finalize(session_id_t session_id);

private:
    leader_instance_t& make_leader(const session_id_t& session_id);
    rpc::client& get_client(int id) {
        std::scoped_lock<std::mutex> lock(this->lockable_clients);
        if(this->clients.find(id) == this->clients.end()) {
            auto log = this->log_pool.at(id);
            this->make_client(log);
        }
        return this->clients.at(id);
    }
    void make_client(logpicker_t& log) {

            this->clients.emplace(std::piecewise_construct,
                                  std::forward_as_tuple(log.get_id()),
                                  std::forward_as_tuple(log.get_hostname(), log.get_port()));

    }

    std::unordered_map<session_id_t, leader_instance_t, session_id_hash_t, session_id_equals_t> leaders;
    Log me;
    boost::asio::io_context& ios;
    std::mutex lockable;
    const log_map_t& log_pool;
    std::unordered_map<int, rpc::client> clients;
    std::mutex lockable_clients;
};


#endif
