#include "logpicker_leader.h"
#include "cert.hpp"
#include "clock_traits.hpp"
#include "debug_log.hpp"
#include "error_out.hpp"

#include <utility>

logpicker_leader_t::logpicker_leader_t(Log me_, const log_map_t& pool_) : me(std::move(me_)),
state(logpicker_state_t::IDLE),
logs(pool_), session_id(), commit_replies(),  commit_replies_signatures(), commit_replies_pool(), commit_replies_count(0), reveals(), reveals_count(0), proof_replies(), proof_replies_log_pool(), proof_replies_signatures(), proof_reply_count(0), lockable() {

}

std::pair<commit_request_t, sigv_t> logpicker_leader_t::start_lp_run(const logpicker_request_t& request) {
    this->session_id = request.get_session_id();
    logpicker_t leader = make_instance(this->me);
    commit_request_t creq(this->session_id, leader, request.get_certificate());
    this->state = logpicker_state_t::SENT_COMMIT_REQUEST;
    lpp::debug_log("Sending commit request\n");
    return{creq, this->sign_message_rsa(creq)};
}

int
logpicker_leader_t::receive_commit_reply(const commit_reply_t &reply, sigv_t sig) {
    this->state = logpicker_state_t::RECEIVED_COMMIT_REPLY;
    lpp::debug_log("Received commit reply\n");
    logpicker_t sender = this->logs.at(reply.get_sender_id());
    if(this->validate_message_rsa(reply, sender.get_rsa_pk(), sig)) {
        lpp::debug_log("Adding commit reply from log {}\n", sender.get_id());
        this->commit_replies.emplace_back(reply);
        this->commit_replies_signatures.emplace_back(sig);
        this->commit_replies_pool.emplace_back(sender.get_id());
        return ++this->commit_replies_count;
    }
    lpp::error_out("Couldn't validate message!");
    this->state = logpicker_state_t::ERROR;
    return -1;
}


int logpicker_leader_t::receive_reveal_reply(const reveal_reply_t &reply, sigv_t sig) {
    this->state = logpicker_state_t::RECEIVED_REVEAL_REPLY;
    lpp::debug_log("Received reveal reply\n");
    logpicker_t sender = this->logs.at(reply.get_sender_id());
    if(this->validate_message_rsa(reply, sender.get_rsa_pk(), sig)) {
        lpp::debug_log("Received reveal reply from log {}\n", sender.get_id());
        this->reveals.emplace_back(reply.get_reveal());
        return ++this->reveals_count;
    }
    lpp::error_out("Couldn't validate message!");
    this->state = logpicker_state_t::ERROR;
    return -1;
}

int logpicker_leader_t::receive_proof_reply(const proof_reply_t &reply, std::pair<sigv_t, sigv_t> sigs) {
    this->state = logpicker_state_t::RECEIVED_PROOF_REPLY;
    lpp::debug_log("Received reveal reply\n");
    logpicker_t sender = this->logs.at(reply.get_sender_id());
    if(this->validate_message_rsa(reply, sender.get_rsa_pk(), sigs.second)) {
        lpp::debug_log("Received proof reply from log {}\n", sender.get_id());
        this->proof_replies.emplace_back(reply);
        this->proof_replies_log_pool.emplace_back(sender.get_id());
        this->proof_replies_signatures.emplace_back(sigs.first);
        return ++this->proof_reply_count;
    }
    lpp::error_out("Couldn't validate message!");
    this->state = logpicker_state_t::ERROR;
    return -1;
}

std::pair<reveal_request_t, sigv_t> logpicker_leader_t::make_reveal_request()  {
    reveal_request_t rr{this->session_id, this->commit_replies_pool, this->commit_replies, this->commit_replies_signatures};
    lpp::debug_log("Sent reveal request\n");
    this->state = logpicker_state_t::SENT_REVEAL_REQUEST;
    return{rr, this->sign_message_rsa(rr)};
}

std::pair<proof_request_t, sigv_t> logpicker_leader_t::make_proof_request() {
    proof_request_t pr{this->session_id, this->reveals};
    this->state = logpicker_state_t::SENT_PROOF_REQUEST;
    lpp::debug_log("Sent proof request\n");
    return{pr, this->sign_message_rsa(pr)};
}

std::pair<std::pair<logpicker_reply_t, sigv_t>,std::pair<finalize_t, sigv_t>> logpicker_leader_t::make_logpicker_reply() {
    aggsigv_t aggsig = crypto::aggregate(this->proof_replies_signatures);
    lpp::debug_log("Aggregating sigs for lpp\n");
    int winner = calculate_winner(this->reveals);
    lpp_t lpp{winner, aggsig, this->proof_replies_log_pool, this->proof_replies};
    logpicker_reply_t lp{this->proof_replies[0.].get_session_id(), this->proof_replies[0].get_sct(), lpp};
    finalize_t fin{this->proof_replies[0.].get_session_id(), lp.get_sct()};

    this->state = logpicker_state_t::FINISHED;
    lpp::debug_log("Finished\n");
    return{{lp,  this->sign_message_rsa(lp)},{fin, this->sign_message_rsa(fin)}};
}

const logpicker_t& logpicker_leader_t::get_log(int log_id) {
    const std::lock_guard<std::mutex> lock(this->lockable);
    return this->logs.at(log_id);
}

