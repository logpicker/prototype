#ifndef LPP_LOGPICKER_MESSAGES_HPP
#define LPP_LOGPICKER_MESSAGES_HPP

#include "rpc/msgpack.hpp"
#include "types.hpp"
#include "logpicker_t.hpp"
#include <functional>

template <typename T, typename... Rest>
inline void hashCombine(std::size_t &seed, T const &v, Rest &&... rest) {
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9U + (seed << 6U) + (seed >> 2U);
    (int[]){0, (hashCombine(seed, std::forward<Rest>(rest)), 0)...};
}


struct session_id_t {
    session_id_t() = default;
    session_id_t(hash_t hash, timestamp_t ts);
    session_id_t(session_id_t&&) = default;
    session_id_t(const session_id_t&) = default;
    constexpr session_id_t& operator=(const session_id_t&) = default;
    constexpr session_id_t& operator=(session_id_t&&) = default;
     hash_t get_cert_hash() const;
     timestamp_t get_timestamp() const;
    hash_t cert_hash;
    timestamp_t timestamp;
    MSGPACK_DEFINE_ARRAY(cert_hash, timestamp)
};

struct session_id_hash_t {
    std::size_t operator()(const session_id_t& k) const
    {
        std::size_t seed = 0UL;
        hashCombine(seed, k.timestamp, k.cert_hash);
        return seed;
    }
};

struct session_id_equals_t {
    bool operator()(const session_id_t& lhs, const session_id_t& rhs) const
    {
        return lhs.cert_hash == rhs.cert_hash && lhs.timestamp == rhs.timestamp;
    }
};

struct logpicker_request_t {
    logpicker_request_t() = default;
    logpicker_request_t(cert_t certificate_, log_pool_t log_pool_, session_id_t session_id_);
    logpicker_request_t(logpicker_request_t&&) = default;
    logpicker_request_t(const logpicker_request_t&) = default;

     cert_t get_certificate() const;
     log_pool_t get_log_pool() const;
     session_id_t get_session_id() const;

    cert_t certificate;
    log_pool_t logs;
    session_id_t session_id;
    MSGPACK_DEFINE_ARRAY(certificate, logs, session_id)

};

struct commit_request_t {
    commit_request_t() = default;
    commit_request_t(session_id_t session_id_, logpicker_t leader_, cert_t certificate_);
    commit_request_t(commit_request_t&&) = default;
    commit_request_t(const commit_request_t&) = default;

     cert_t get_certificate() const;
     logpicker_t get_leader() const;
     session_id_t get_session_id() const;

    session_id_t session_id;
    logpicker_t leader;
    cert_t certificate;
    MSGPACK_DEFINE_ARRAY(session_id, leader, certificate)
};

struct commit_reply_t {
    commit_reply_t() = default;
    commit_reply_t(session_id_t session_id_, int sender_id_, hash_t commit_);
    commit_reply_t(commit_reply_t&&) = default;
    commit_reply_t(const commit_reply_t&) = default;

     int get_sender_id() const;
     hash_t get_commit() const;
     session_id_t get_session_id() const;

    session_id_t session_id;
    int sender_id;
    hash_t commit;
    MSGPACK_DEFINE_ARRAY(session_id, sender_id, commit)
};

struct reveal_request_t {

    reveal_request_t() = default;
    reveal_request_t(session_id_t session_id_, log_pool_t log_pool_, std::vector<commit_reply_t> commits_, std::vector<sigv_t> signatures_);
    reveal_request_t(reveal_request_t&&) = default;
    reveal_request_t(const reveal_request_t&) = default;

     log_pool_t get_log_pool() const;
     session_id_t get_session_id() const;
     std::vector<commit_reply_t> get_commits() const;
     std::vector<sigv_t>  get_signatures() const;
    session_id_t session_id;
    log_pool_t log_pool;
    std::vector<commit_reply_t> commits;
    std::vector<sigv_t> signatures;
    MSGPACK_DEFINE_ARRAY(session_id, log_pool, commits, signatures)
};

struct reveal_reply_t {
    reveal_reply_t() = default;
    reveal_reply_t(session_id_t session_id_, int sender_id_, reveal_t reveal_);
    reveal_reply_t(reveal_reply_t&&) = default;
    reveal_reply_t(const reveal_reply_t&) = default;

     int get_sender_id() const;
     reveal_t get_reveal() const;
     session_id_t get_session_id() const;

    session_id_t session_id;
    int sender_id;
    reveal_t reveal;
    MSGPACK_DEFINE_ARRAY(session_id, sender_id, reveal)
};

struct proof_request_t {

    proof_request_t() = default;
    proof_request_t(session_id_t session_id_, std::vector<reveal_t> reveals_);
    proof_request_t(proof_request_t&&) = default;
    proof_request_t(const proof_request_t&) = default;

     session_id_t get_session_id() const;
     std::vector<reveal_t> get_reveals() const;

    session_id_t session_id;
    std::vector<reveal_t> reveals;

    MSGPACK_DEFINE_ARRAY(session_id, reveals)
};

// TODO: Dummy sct implementation
struct sct_t {
    sct_t() = default;
    sct_t(sct_t&&) = default;
    sct_t(const sct_t&) = default;

    explicit sct_t(std::vector<uint8_t> data_);

     std::vector<uint8_t> get_data() const;
    std::vector<uint8_t> data;
    MSGPACK_DEFINE_ARRAY(data)
};



struct proof_reply_t {
    proof_reply_t() = default;
    proof_reply_t(session_id_t session_id_, int sender_id_, sct_t sct_, int result_);
    proof_reply_t(proof_reply_t&&) = default;
    proof_reply_t(const proof_reply_t&) = default;

     int get_sender_id() const;
     sct_t get_sct() const;
     int get_result() const;
     session_id_t get_session_id() const;

    session_id_t session_id;
    int sender_id;
    int result;
    sct_t sct;

    MSGPACK_DEFINE_ARRAY(session_id, sender_id, result, sct)
};

// TODO: Dummy lpp implementation
struct lpp_t {
    lpp_t() = default;
    explicit lpp_t(int winner_, aggsigv_t signature_, log_pool_t log_pool_, std::vector<proof_reply_t> proof_replies_);
    lpp_t(lpp_t&&) = default;
    lpp_t(const lpp_t&) = default;

     int get_winner() const;
     int get_version() const;
     aggsigv_t get_signature() const;
     log_pool_t get_log_pool() const;
     std::vector<proof_reply_t> get_proof_replies() const;

    int winner;
    int version;
    aggsigv_t signature;
    log_pool_t log_pool;
    std::vector<proof_reply_t> proof_replies;
    MSGPACK_DEFINE_ARRAY(winner, version, signature, log_pool, proof_replies)
};

struct finalize_t {
    finalize_t() = default;
    finalize_t(session_id_t session_id_, sct_t sct_);
    finalize_t(finalize_t&&) = default;
    finalize_t(const finalize_t&) = default;

     session_id_t get_session_id() const;
     sct_t get_sct() const;

    session_id_t session_id;
    sct_t sct;
    MSGPACK_DEFINE_ARRAY(session_id, sct)
};

struct logpicker_reply_t {
    logpicker_reply_t() = default;
    logpicker_reply_t(session_id_t session_id_,sct_t sct_, lpp_t lpp);
    logpicker_reply_t(logpicker_reply_t&&) = default;
    logpicker_reply_t(const logpicker_reply_t&) = default;

     session_id_t get_session_id() const;


     sct_t get_sct() const;
     lpp_t get_lpp() const;

    session_id_t session_id;
    sct_t sct;
    lpp_t lpp;
    MSGPACK_DEFINE_ARRAY(session_id, sct, lpp)
};
#endif
