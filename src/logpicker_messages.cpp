#include "logpicker_messages.hpp"

#include <utility>

session_id_t::session_id_t(hash_t hash, timestamp_t ts) : cert_hash(hash), timestamp(ts) {

}

hash_t session_id_t::get_cert_hash() const {
    return this->cert_hash;
}

timestamp_t session_id_t::get_timestamp() const {
    return this->timestamp;
}


logpicker_request_t::logpicker_request_t(cert_t certificate_, log_pool_t log_pool_, session_id_t session_id_) : certificate(std::move(certificate_)), logs(std::move(log_pool_)), session_id(session_id_) {

}

cert_t logpicker_request_t::get_certificate() const {
    return this->certificate;
}

log_pool_t logpicker_request_t::get_log_pool() const {
    return this->logs;
}

session_id_t logpicker_request_t::get_session_id() const {
    return this->session_id;
}

commit_request_t::commit_request_t(session_id_t session_id_, logpicker_t leader_, cert_t certificate_) : session_id(session_id_), leader(std::move(leader_)), certificate(std::move(certificate_)) {

}

cert_t commit_request_t::get_certificate() const {
    return this->certificate;
}

logpicker_t commit_request_t::get_leader() const {
    return this->leader;
}

session_id_t commit_request_t::get_session_id() const {
    return this->session_id;
}

hash_t commit_reply_t::get_commit() const {
    return this->commit;
}

int commit_reply_t::get_sender_id() const {
    return this->sender_id;
}

session_id_t commit_reply_t::get_session_id() const {
    return this->session_id;
}

commit_reply_t::commit_reply_t(session_id_t session_id_, int sender_id_, hash_t commit_) : session_id(session_id_), sender_id(sender_id_), commit(commit_) {

}

reveal_request_t::reveal_request_t(session_id_t session_id_, log_pool_t log_pool_, std::vector<commit_reply_t> commits_, std::vector<sigv_t> signatures_) : session_id(session_id_), log_pool(std::move(log_pool_)), commits(std::move(commits_)), signatures(std::move(signatures_)) {

}

log_pool_t reveal_request_t::get_log_pool() const {
    return this->log_pool;
}

session_id_t reveal_request_t::get_session_id() const {
    return this->session_id;
}

std::vector<commit_reply_t> reveal_request_t::get_commits() const {
    return this->commits;
}

std::vector<sigv_t> reveal_request_t::get_signatures() const {
    return this->signatures;
}

reveal_reply_t::reveal_reply_t(session_id_t session_id_, int sender_id_, reveal_t reveal_) : session_id(session_id_), sender_id(sender_id_), reveal(reveal_) {

}

int reveal_reply_t::get_sender_id() const {
    return this->sender_id;
}

reveal_t reveal_reply_t::get_reveal() const {
    return this->reveal;
}

session_id_t reveal_reply_t::get_session_id() const {
    return this->session_id;
}

sct_t::sct_t(std::vector<uint8_t> data_) : data(std::move(data_)) {

}

std::vector<uint8_t> sct_t::get_data() const {
    return this->data;
}

proof_reply_t::proof_reply_t(session_id_t session_id_, int sender_id_, sct_t sct_, int result_) : session_id(session_id_), sender_id(sender_id_), result(result_), sct(std::move(sct_)) {

}

session_id_t proof_reply_t::get_session_id() const {
    return this->session_id;
}

int proof_reply_t::get_sender_id() const {
    return this->sender_id;
}

sct_t proof_reply_t::get_sct() const {
    return this->sct;
}

int proof_reply_t::get_result() const {
    return this->result;
}

proof_request_t::proof_request_t(session_id_t session_id_, std::vector<reveal_t> reveals_) : session_id(session_id_), reveals(std::move(reveals_)) {

}

session_id_t proof_request_t::get_session_id() const {
    return this->session_id;
}

std::vector<reveal_t> proof_request_t::get_reveals() const {
    return this->reveals;
}

finalize_t::finalize_t(session_id_t session_id_,  sct_t sct_) : session_id(session_id_), sct(std::move(sct_))  {

}
session_id_t finalize_t::get_session_id() const {
    return this->session_id;
}
sct_t finalize_t::get_sct() const {
    return this->sct;
}

logpicker_reply_t::logpicker_reply_t(session_id_t session_id_, sct_t sct_, lpp_t lpp_) : session_id(session_id_), sct(std::move(sct_)), lpp(std::move(lpp_)) {

}

session_id_t logpicker_reply_t::get_session_id() const {
    return this->session_id;
}

sct_t logpicker_reply_t::get_sct() const {
    return this->sct;
}

lpp_t logpicker_reply_t::get_lpp() const {
    return this->lpp;
}

lpp_t::lpp_t(int winner_, aggsigv_t signature_, log_pool_t log_pool_, std::vector<proof_reply_t> proof_replies_) : winner(winner_), version(1), signature(std::move(signature_)), log_pool(std::move(log_pool_)), proof_replies(std::move(proof_replies_)) {

}
int lpp_t::get_winner() const {
    return this->winner;
}

int lpp_t::get_version() const {
    return this->version;
}

std::vector<proof_reply_t> lpp_t::get_proof_replies() const {
    return this->proof_replies;
}

aggsigv_t lpp_t::get_signature() const {
    return this->signature;
}

log_pool_t lpp_t::get_log_pool() const {
    return this->log_pool;
}