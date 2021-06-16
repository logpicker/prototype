#include "leader_instance.h"

#include <utility>
#include "error_out.hpp"
#include <rpc/client.h>

leader_instance_t::leader_instance_t(Log l, boost::asio::io_context& ios_, const log_map_t& log_pool_, std::function<void(session_id_t)> callback_, std::function<void(logpicker_t&)> make_client_, std::function<rpc::client&(int)> get_client_) : me(std::move(l), log_pool_), pool(), q(-1), finalized_received(0), start_ts(-1), end_ts(-1), ios(ios_), callback(std::move(callback_)), log_pool(log_pool_), make_client(std::move(make_client_)), get_client(std::move(get_client_)) {

}

bool leader_instance_t::start_run(const logpicker_request_t& req) {
    lpp::printfn("Received start run request!\n");
    std::pair<commit_request_t, sigv_t> ret = this->me.start_lp_run(req);
    lpp::printfn("Started lp run\n");
    this->q = req.get_log_pool().size();
    lpp::printfn("Set q to: {}\n", this->q);
    for(int log_id : req.get_log_pool()) {
        auto log = this->log_pool.at(log_id);
        this->pool.emplace_back(log_id);
        this->make_client(log);
    }
    this->start_ts = current_timestamp();
    for(int log_id : req.get_log_pool()) {
        //auto log = this->log_pool.at(log_id);
        lpp::printfn("Sending commit request to {}\n", log_id);

        this->ios.dispatch([this, ret, log_id]() {
            auto r = this->get_client(log_id).call("commit_request", ret.first, ret.second).as<std::pair<commit_reply_t, sigv_t>>();
            this->receive_commit_reply(r.first, r.second);
        });
    }
    return true;
}

int leader_instance_t::receive_commit_reply(commit_reply_t reply, const sigv_t& sig) {
    lpp::printfn("Received commit reply!\n");
    int v = this->me.receive_commit_reply(reply, sig);
    lpp::printfn("Processed commit reply #{}!\n", v);
    if(v == this->q) {
        lpp::printfn("Q reached at {}\n", this->q);
        std::pair<reveal_request_t, sigv_t> ret = this->me.make_reveal_request();
        for (int log_id: this->pool) {
            //auto log = this->log_pool.at(log_id);
            lpp::printfn("Sending reveal request to {}\n", log_id);
            this->ios.dispatch([this, ret, log_id]() {
                auto r = this->get_client(log_id).call("reveal_request", ret.first, ret.second).as<std::pair<reveal_reply_t, sigv_t>>();
                this->receive_reveal_reply(r.first, r.second);
            });
        }
    }
    return v;
}

bool leader_instance_t::receive_proof_reply(const proof_reply_t& reply, std::pair<sigv_t, sigv_t> sigs) {
    lpp::printfn("Received proof reply!\n");
    int v = this->me.receive_proof_reply(reply, std::move(sigs));
    lpp::printfn("Processed proof reply #{}!\n", v);
    if(v == this->q) {
        lpp::printfn("PR: Q reached at {}\n", this->q);
        auto r = this->me.make_logpicker_reply();
        this->end_ts = current_timestamp();
        lpp::error_out("{},{},{},{}\n", this->q, this->start_ts, this->end_ts, (this->end_ts - this->start_ts));
        std::pair<logpicker_reply_t, sigv_t> lpr = r.first;
        std::pair<finalize_t, sigv_t> fin = r.second;
        for (int log_id : this->pool) {
            //auto log = this->log_pool.at(log_id);
            this->ios.dispatch([this, fin, log_id]() {
                bool vi = this->get_client(log_id).call("finalize", fin.first, fin.second).as<bool>();
                lpp::printfn("Removing client: {}: {}\n", log_id, vi);
                this->finalized_received++;
                if(finalized_received.load() == this->q) {
                    session_id_t sid = fin.first.get_session_id();
                    this->callback(sid);
                }
            });
        }
        return true;
    }
    return false;
}

int leader_instance_t::receive_reveal_reply(const reveal_reply_t& reply, const sigv_t& sig) {
    lpp::printfn("Received reveal reply!\n");
    int v = this->me.receive_reveal_reply(reply, sig);
    lpp::printfn("Processed reveal reply #{}!\n", v);
    if(v == this->q) {
        lpp::printfn("RR: Q reached at {}\n", this->q);
        std::pair<proof_request_t, sigv_t> r = this->me.make_proof_request();
        for (int log_id : this->pool) {
            lpp::printfn("Sending proof request to {}\n", log_id);
            this->ios.dispatch([this, r, log_id]() {
                auto ret = this->get_client(log_id).call("proof_request", r.first, r.second).as<std::pair<proof_reply_t, std::pair<sigv_t, sigv_t>>>();
                this->receive_proof_reply(ret.first, ret.second);
            });
        }
    }
    return v;
}

