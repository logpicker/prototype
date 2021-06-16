#include "logpicker_instance.hpp"
#include <utility>
#include "debug_log.hpp"
#include "error_out.hpp"

std::pair<commit_reply_t, sigv_t> logpicker_instance::receive_commit_request(const commit_request_t& req,  sigv_t sig) {
    lpp::debug_log("Received commit request\n");
    this->state = logpicker_state_t::RECEIVED_COMMIT_REQUEST;
    this->leader = req.get_leader();
    auto bs = bls::Util::HexToBytes(this->leader.get_rsa_pk());
    rsa_key_read_bin(this->leader_pk, bs.data());
    if(this->validate_message_rsa(req, sig)) {
        this->reveal = this->dist(this->rnd_engine);
        this->commit = std::hash<reveal_t>{}(this->reveal);
        commit_reply_t reply{req.get_session_id(), this->me.get_id(), commit};
        this->state = logpicker_state_t::SENT_COMMIT_REPLY;
        lpp::debug_log("Sent commit reply\n");
        return{reply, this->sign_message_rsa(reply)};
    }
    std::cout << "Couldn't validate message!";
    this->state = logpicker_state_t::ERROR;
    return{};
}

std::pair<reveal_reply_t, sigv_t> logpicker_instance::receive_reveal_request(const reveal_request_t& req, sigv_t sig) {
    lpp::debug_log("Received reveal request\n");
    this->state = logpicker_state_t::RECEIVED_COMMIT_REQUEST;
    if(this->validate_message_rsa(req, sig)) {
        log_pool_t logs = req.get_log_pool();
        std::vector<commit_reply_t> crs = req.get_commits();
        std::vector<sigv_t> signatures = req.get_signatures();
        for(size_t i = 0; i < logs.size(); i++) {
            const logpicker_t& log = this->log_pool.at(i);
            commit_reply_t cr = crs[i];
            sigv_t signature = signatures[i];
            std::string pkv = log.get_rsa_pk();
            rsa_t pk;
            auto bs = bls::Util::HexToBytes(pkv);
            rsa_key_read_bin(pk, bs.data());
            bool valid = this->validate_message_rsa(cr, signature, pk);
            if(!valid) {
                lpp::error_out("Couldn't validate cr at idx: {}!\n", i);
                this->state = logpicker_state_t::ERROR;
                return{};
            }
        }
        reveal_reply_t rr{req.get_session_id(), this->me.get_id(), this->reveal};
        this->state = logpicker_state_t::SENT_REVEAL_REPLY;
        lpp::debug_log("Sent reveal reply\n");
        return{rr, this->sign_message_rsa(rr)};
    }
    lpp::error_out("Couldn't validate message!");
    this->state = logpicker_state_t::ERROR;
    return{};
}

logpicker_instance::logpicker_instance(Log me_, const log_map_t& log_pool_, std::default_random_engine& rnd_engine_, std::uniform_int_distribution<reveal_t>& dist_) : me(std::move(me_)), leader(), state(logpicker_state_t::IDLE), reveal(), commit(), log_pool(log_pool_), rnd_engine(rnd_engine_), dist(dist_) {
    rsa_new(this->leader_pk);
}

std::pair<proof_reply_t, std::pair<sigv_t, sigv_t>> logpicker_instance::receive_proof_request(const proof_request_t& req, sigv_t sig) {
    lpp::debug_log("Received proof request\n");
    this->state = logpicker_state_t::RECEIVED_PROOF_REQUEST;

    if(this->validate_message_rsa(req, sig)) {
        int winner = calculate_winner(req.get_reveals());
        if(this->me.get_id() == winner) {
            sct_t sct{random_data()};
            proof_reply_t pr{req.get_session_id(), this->me.get_id(), sct, winner};
            lpp::debug_log("Sent proof reply as the winner!\n");
            this->state = logpicker_state_t::SENT_PROOF_REPLY;
            return{pr, {this->sign_message(pr).Serialize(), this->sign_message_rsa(pr)}};
        }
        sct_t sct{};
        proof_reply_t pr{req.get_session_id(), this->me.get_id(), sct, winner};
        lpp::debug_log("Sent proof reply as a loser!\n");
        this->state = logpicker_state_t::SENT_PROOF_REPLY;
        return{pr, {this->sign_message(pr).Serialize(), this->sign_message_rsa(pr)}};
    }
    lpp::error_out("Couldn't validate message!");
    this->state = logpicker_state_t::ERROR;
    return{};}

bool logpicker_instance::finalize(const finalize_t &fin, sigv_t sig) {
    return this->validate_message_rsa(fin, sig);
}


