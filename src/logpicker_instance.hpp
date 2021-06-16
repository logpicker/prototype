#ifndef LPP_LOGPICKER_INSTANCE_HPP
#define LPP_LOGPICKER_INSTANCE_HPP
#include "types.hpp"
#include "logpicker_messages.hpp"
#include "logpicker_state.hpp"

#include "log.hpp"
#include "utils.hpp"
#include "crypto.hpp"
#include "printfn.hpp"

class logpicker_instance {

public:
    logpicker_instance(Log me_, const log_map_t& log_pool_, std::default_random_engine& rnd_engine_, std::uniform_int_distribution<reveal_t>& dist_);

    std::pair<commit_reply_t, sigv_t> receive_commit_request(const commit_request_t& req, sigv_t sig);

    std::pair<reveal_reply_t, sigv_t> receive_reveal_request(const reveal_request_t& req, sigv_t sig);

    std::pair<proof_reply_t, std::pair<sigv_t, sigv_t>> receive_proof_request(const proof_request_t& req, sigv_t sig);

    bool finalize(const finalize_t& fin, sigv_t sig);

private:
    Log me;
    logpicker_t leader;
    logpicker_state_t state;
    reveal_t reveal;
    hash_t commit;
    const log_map_t& log_pool;
    std::default_random_engine& rnd_engine;
    std::uniform_int_distribution<reveal_t>& dist;
    rsa_t leader_pk;

    template<typename T>
    bool validate_message(const T &msg, const sigv_t &sig) {
        return crypto::verify(leader.get_pkv(), message_contents(msg), sig);
    }

    template<typename T>
    bool validate_message(const T &msg, const pkv_t& pkv, const sigv_t &sig) {
        return crypto::verify(pkv, message_contents(msg), sig);
    }

    template<typename T>
    bool validate_message_rsa(const T &msg, sigv_t &sig) {
        msg_t msgv = message_contents(msg);
        auto ret = cp_rsa_ver(sig.data(),
                              sig.size(), msgv.data(), msgv.size(), 0, this->leader_pk);
        return ret == 1;
        //return true;
    }
    template<typename T>
    bool validate_message_rsa(const T &msg, sigv_t &sig, rsa_t& pk) {
        msg_t msgv = message_contents(msg);
        auto ret = cp_rsa_ver(sig.data(),
                              sig.size(), msgv.data(), msgv.size(), 0, pk);
        return ret == 1;
        //return true;
    }

    template<typename T>
    signature_t sign_message(const T &msg) {
        msg_t msgv = message_contents(msg);
        return me.sign(msgv);
    }

    template<typename T>
    sigv_t sign_message_rsa(const T &msg) {
        msg_t msgv = message_contents(msg);
        return me.sign_rsa(msgv);
    }

    template<typename T>
    sigv_t sign_rsa_message(const T &msg) {
        msg_t msgv = message_contents(msg);
        return me.sign_rsa(msgv);
    }

};
#endif
