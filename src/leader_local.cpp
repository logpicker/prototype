#include "leader.h"
#include "log.hpp"
#include "logpicker_leader.h"
#include <rpc/client.h>
#include "rpc/server.h"
#include "error_out.hpp"
#include "utils.hpp"
#include "cert.hpp"
#include <thread>


int main(int argc, char **argv) {
    std::string arg = argv[1];
    int cnt = std::stoi(arg);
    std::string config_filename = argv[2];
    std::string cert_filename = argv[3];
    cert_t cert = read_cert_from_disk(cert_filename);
    //cert.resize(32);
    log_pool_t lp;
    for(int i = 0; i < cnt; i++) {
        //auto log = Log::read_log(config_filename, i);
        lp.emplace_back(i);
    }
    boost::asio::io_context ios;
    Log l = Log::read_leader(config_filename);
    log_map_t pool = read_log_pool(config_filename);
    leader_t leader(ios, l, pool);
    auto port = rpc::constants::DEFAULT_PORT - 1;
    lpp::printfn("Starting leader instance {} on port: {}\n", l.get_id(), port);
    rpc::server srv("0.0.0.0", port);

    srv.bind("start_run", [&leader](const logpicker_request_t& req){ leader.start_run(req); return true;});
    lpp::printfn("Starting leader \n");
    srv.suppress_exceptions(false);
    srv.async_run(64);
    std::thread submitter([&ios, &lp, &cert, &leader]() {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        for(int i = 0; i < 100; i++) {
            session_id_t sid(hash_certificate(cert), current_timestamp_sid());
            logpicker_request_t lp_request{cert, lp, sid};
            leader.start_run(lp_request);
        }
    });
    leader.run(32);


    ios.run();
    std::cin.ignore();
    return 0;

}
