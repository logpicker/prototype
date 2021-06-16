#include "logpicker_messages.hpp"

#include "cert.hpp"
#include "types.hpp"
#include "log.hpp"
#include "utils.hpp"
#include "logpicker_instance.hpp"
#include "logpicker_leader.h"
#include "clock_traits.hpp"
#include "debug_log.hpp"
#include "printfn.hpp"
#include "error_out.hpp"
#include <cassert>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

namespace pt = boost::property_tree;

pt::ptree save_config(const std::vector<Log>& logs, Log leader) {
    pt::ptree tree;
    pt::ptree lt = leader.to_ptree();
    tree.add_child("lpp.leader", lt);
    pt::ptree logs_node;
    for(const Log& log : logs) {
        logs_node.push_back(std::pair("log", log.to_ptree()));
    }
    tree.add_child("lpp.logs", logs_node);
    return tree;
}

bool validate_logpicker_reply(const logpicker_reply_t& reply, const log_map_t& pool) {
    std::vector<msg_t> msgs;
    std::vector<pkv_t> pks;
    lpp_t lpp = reply.get_lpp();
    for(const auto& pr : lpp.proof_replies) {
        msgs.emplace_back(message_contents(pr));
    }
    for(const auto& log : lpp.log_pool) {
        pks.emplace_back(pool.at(log).get_pkv());
    }
    return crypto::verify_aggsig(pks, msgs, lpp.get_signature());
}



int main(int argc, char **argv) {
    std::string config_filename = "/home/leen/Projects/TU_BS/misc/LogPicker/lpp/data/config.xml";
    std::string cert_filename = "/home/leen/Projects/TU_BS/misc/LogPicker/lpp/data/github/DER/github.com";
    if(argc == 3) {
        config_filename = std::string(argv[1]);
        cert_filename = std::string(argv[2]);
    }

    cert_t cert = read_cert_from_disk(cert_filename);
    std::random_device rnd_device;
    std::default_random_engine rnd_engine(rnd_device());
    std::uniform_int_distribution<reveal_t> uniform_dist(std::numeric_limits<reveal_t>::min(), std::numeric_limits<reveal_t>::max());
    std::vector<Log> p = make_logs(200);
    log_pool_t lpi;
    std::vector<logpicker_t> lp;
    log_map_t lm;
    int i = 0;
    for(const auto& log : p) {
        lp.emplace_back(make_instance(log));
        lm.emplace(log.get_id(), make_instance(log));
        lpi.emplace_back(i++);
    }
    std::vector<logpicker_instance> instances;
    for(const auto& log: p) {
        instances.emplace_back(log, lm, rnd_engine, uniform_dist);
    }

    Log leader(std::numeric_limits<uint8_t>::max(), "127.0.0.1", vector<uint8_t>(32, std::numeric_limits<uint8_t>::max()));

    for(int i = 0; i < 5; i++) {
        Log ll = Log::read_leader(config_filename);
        logpicker_leader_t lpp_leader(ll, lm);
        session_id_t sid(hash_certificate(cert), current_timestamp());

        logpicker_request_t lp_request{cert, lpi, sid};

        auto before_lp = clock_traits::clock_type_t::now();

        std::pair<commit_request_t, sigv_t> initial = lpp_leader.start_lp_run(lp_request);

        lpp::error_out("instances size: {}\n", instances.size());
        size_t commit_reply_count = 0;
        for (auto &instance : instances) {
            std::pair<commit_reply_t, sigv_t> cr = instance.receive_commit_request(initial.first, initial.second);
            commit_reply_count = lpp_leader.receive_commit_reply(cr.first, cr.second);
        }

        lpp::error_out("Commit reply count size: {}\n", commit_reply_count);
        assert(commit_reply_count == instances.size());
        std::pair<reveal_request_t, sigv_t> rr = lpp_leader.make_reveal_request();
        size_t reveal_reply_count = 0;
        for (auto &instance : instances) {
            std::pair<reveal_reply_t, sigv_t> rrpl = instance.receive_reveal_request(rr.first, rr.second);
            reveal_reply_count = lpp_leader.receive_reveal_reply(rrpl.first, rrpl.second);
        }
        lpp::error_out("Reveal reply count size: {}\n", reveal_reply_count);
        assert(reveal_reply_count == instances.size());
        std::pair<proof_request_t, sigv_t> pr = lpp_leader.make_proof_request();
        size_t proof_reply_count = 0;
        for (auto &instance : instances) {
            std::pair<proof_reply_t, std::pair<sigv_t, sigv_t>> prpl = instance.receive_proof_request(pr.first, pr.second);
            proof_reply_count = lpp_leader.receive_proof_reply(prpl.first, prpl.second);
        }
        lpp::error_out("Proof reply count size: {}\n", proof_reply_count);
        assert(proof_reply_count == instances.size());
        auto r = lpp_leader.make_logpicker_reply();
        std::pair<logpicker_reply_t, sigv_t> lpr = r.first;
        auto after_lp = clock_traits::clock_type_t::now();
        auto dur = std::chrono::duration_cast<clock_traits::time_unit>(after_lp - before_lp);
    }
}
