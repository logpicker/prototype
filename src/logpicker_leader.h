#ifndef LPP_LOGPICKER_LEADER_H
#define LPP_LOGPICKER_LEADER_H


#include "log.hpp"
#include "logpicker_instance.hpp"
#include "printfn.hpp"
#include <mutex>
extern "C" {
#include "relic.h"
#include "rsa_util.h"
}
class logpicker_leader_t {
public:
    explicit logpicker_leader_t(Log me_, const log_map_t& pool_);
    std::pair<commit_request_t, sigv_t> start_lp_run(const logpicker_request_t&);
    int receive_commit_reply(const commit_reply_t& reply, sigv_t sig);
    std::pair<reveal_request_t, sigv_t> make_reveal_request();
    int receive_reveal_reply(const reveal_reply_t& reply, sigv_t sig);
    std::pair<proof_request_t, sigv_t> make_proof_request();
    int receive_proof_reply(const proof_reply_t& reply, std::pair<sigv_t, sigv_t> sigs);
    std::pair<std::pair<logpicker_reply_t, sigv_t>,std::pair<finalize_t, sigv_t>> make_logpicker_reply();

private:
    Log me;
    logpicker_state_t state;
    const log_map_t& logs;
    session_id_t session_id;
    std::vector<commit_reply_t> commit_replies;
    std::vector<sigv_t> commit_replies_signatures;
    log_pool_t commit_replies_pool;
    int commit_replies_count;
    std::vector<reveal_t> reveals;
    int reveals_count;
    std::vector<proof_reply_t> proof_replies;
    log_pool_t proof_replies_log_pool;
    std::vector<sigv_t> proof_replies_signatures;
    int proof_reply_count;
    std::mutex lockable;

    const logpicker_t& get_log(int log_id);

    template<typename T>
    bool validate_message(const T &msg, const pkv_t& pkv, const sigv_t &sig) {
        msg_t msgv = message_contents(msg);
        return crypto::verify(pkv, msgv, sig);
    }

    template<typename T>
    bool validate_message_rsa(const T &msg, const std::string& pkv, sigv_t &sig) {
        rsa_t pk;
        auto bs = bls::Util::HexToBytes(pkv);
        rsa_key_read_bin(pk, bs.data());
        msg_t msgv = message_contents(msg);
        auto ret = cp_rsa_ver(sig.data(),
                              sig.size(), msgv.data(), msgv.size(), 0, pk);
        return ret == 1;
    }

    template<typename T>
    sigv_t sign_message_rsa(const T &msg) {
        msg_t msgv = message_contents(msg);
        return me.sign_rsa(msgv);
    }

    template<typename T>
    signature_t sign_message(const T &msg) const {
        msg_t msgv = message_contents(msg);
        return me.sign(msgv);
    }
};


#endif
