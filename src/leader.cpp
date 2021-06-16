#include "leader.h"
#include "log.hpp"
#include "logpicker_leader.h"
#include <rpc/client.h>

#include <utility>
#include "error_out.hpp"
#include <boost/thread.hpp>
#include <functional>
#include "utils.hpp"

namespace asio = boost::asio;


void leader_t::start_run(const logpicker_request_t& req) {
    this->ios.dispatch([this, req]() {
        session_id_t sid = req.get_session_id();
        leader_instance_t& l = this->make_leader(sid);
        l.start_run(req);
    });
}

leader_t::leader_t(boost::asio::io_context& ios_, Log l, const log_map_t& log_pool_) : me(std::move(l)), ios(ios_), lockable(), log_pool(log_pool_), clients() {
    clients.reserve(log_pool_.size());
    /*for(auto log : log_pool_) {
        this->make_client(log.second);
    }*/
}

void leader_t::finalize(session_id_t session_id) {
    const std::lock_guard<std::mutex> lock(this->lockable);
    this->leaders.erase(session_id);
}

void leader_t::run(size_t concurrency_level) {
    std::unique_ptr<asio::io_service::work> work(new asio::io_service::work(this->ios));
    boost::thread_group threads;
    for(size_t i = 0; i < concurrency_level; ++i) {
        threads.create_thread([this]() { this->ios.run(); });
    }
    this->ios.run();
}

leader_instance_t &leader_t::make_leader(const session_id_t &session_id) {
    const std::lock_guard<std::mutex> lock(this->lockable);
    this->leaders.emplace(std::piecewise_construct,
                          std::forward_as_tuple(session_id),
                          std::forward_as_tuple(
                                  this->me,
                                  this->ios,
                                  this->log_pool,
                                  [this](session_id_t sid) { this->finalize(sid); },
                                  [this](logpicker_t log) {  },
                                  [this](int log_id) -> rpc::client & {
                                      return this->get_client(log_id);
                                  }));
    return this->leaders.at(session_id);
}
