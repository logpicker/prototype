#include <iostream>
#include <rpc/client.h>
#include "rpc/server.h"
#include "types.hpp"
#include "log.hpp"
#include "printfn.hpp"
#include "logpicker_messages.hpp"
#include "logpicker_instance.hpp"
#include <random>

int main(int argc, char **argv) {
    std::string arg = argv[1];
    int idx = std::stoi(arg);
    //std::string config_filename = "/home/i1000666/lpp/data/config.xml";
    std::string config_filename = argv[2];

    log_map_t pool = read_log_pool(config_filename);
    Log l = Log::read_log(config_filename, idx).value();
    auto port = rpc::constants::DEFAULT_PORT + l.get_id();
    lpp::printfn("Starting log instance {} on port: {}\n", l.get_id(), port);
    rpc::server srv("0.0.0.0", port);
    std::random_device rnd_device;
    std::mutex lockable;
    std::default_random_engine rnd_engine(rnd_device());
    std::uniform_int_distribution<reveal_t> uniform_dist(std::numeric_limits<reveal_t>::min(), std::numeric_limits<reveal_t>::max());
    std::unordered_map<session_id_t, logpicker_instance, session_id_hash_t, session_id_equals_t> workers{};
    srv.bind("commit_request", [&lockable, &l, &workers, &pool, &rnd_engine, &uniform_dist](const commit_request_t& req, const sigv_t& sig) {
        session_id_t sid = req.get_session_id();
        {
            const std::lock_guard<std::mutex> lock(lockable);


            workers.emplace(std::piecewise_construct,
                            std::forward_as_tuple(sid),
                            std::forward_as_tuple(l, pool, rnd_engine, uniform_dist));
        }
        return workers.at(sid).receive_commit_request(req, sig);
    });
    srv.bind("reveal_request", [&workers](const reveal_request_t& req, const sigv_t& sig) {
        return workers.at(req.get_session_id()).receive_reveal_request(req, sig);
    });
    srv.bind("proof_request", [&workers](const proof_request_t& req, const sigv_t& sig) {
        return workers.at(req.get_session_id()).receive_proof_request(req, sig);
    });
    srv.bind("finalize", [&lockable, &workers](const finalize_t& fin, const sigv_t& sig) {
        if(workers.at(fin.get_session_id()).finalize(fin, sig)) {
            {
                const std::lock_guard<std::mutex> lock(lockable);
                workers.erase(fin.get_session_id());
            }
            lpp::printfn("Removed server instance!\n");
            return true;
        }
        return false;
    });

    srv.suppress_exceptions(false);

    // Run the server loop.
    srv.async_run(20);
    std::cin.ignore();
    return 0;
}
