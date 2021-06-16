#ifndef LPP_LEADER_INSTANCE_H
#define LPP_LEADER_INSTANCE_H

#include <unordered_map>
#include "logpicker_leader.h"
#include "clock_traits.hpp"
#include <boost/asio.hpp>
#include <rpc/client.h>

#include <atomic>

class leader_instance_t {
    public:
        leader_instance_t(Log l, boost::asio::io_context& ios_, const log_map_t& log_pool_, std::function<void(session_id_t)> , std::function<void(logpicker_t&)> make_client_, std::function<rpc::client&(int)> get_client_);
        bool start_run(const logpicker_request_t& req);

        int receive_commit_reply(commit_reply_t reply, const sigv_t& sig);
        int receive_reveal_reply(const reveal_reply_t& reply, const sigv_t& sig);

        bool receive_proof_reply(const proof_reply_t& reply, std::pair<sigv_t, sigv_t> sigs);
    private:
        logpicker_leader_t me;
        log_pool_t pool;
        int q;
        std::atomic<int> finalized_received;
        int64_t start_ts;
        int64_t end_ts;
        boost::asio::io_context& ios;
        std::function<void(session_id_t)> callback;
        std::mutex lockable;
        const log_map_t& log_pool;
        std::function<void(logpicker_t&)> make_client;
        std::function<rpc::client&(int)> get_client;
    };

#endif
