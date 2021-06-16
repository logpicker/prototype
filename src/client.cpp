#include <iostream>
#include "rpc/client.h"
#include "rpc/rpc_error.h"
#include "types.hpp"
#include "log.hpp"
#include "logpicker_t.hpp"
#include "cert.hpp"
#include "logpicker_messages.hpp"
#include "clock_traits.hpp"
#include "printfn.hpp"
#include "error_out.hpp"
#include <thread>

int main(int argc, char **argv) {
    std::string arg = argv[1];
    int cnt = std::stoi(arg);
    std::string config_filename = argv[2];
    std::string cert_filename = argv[3];
    cert_t cert = read_cert_from_disk(cert_filename);
    Log leader = Log::read_leader(config_filename);
    //cert.resize(32);
    log_pool_t lp;
    for(int i = 0; i < cnt; i++) {
        //auto log = Log::read_log(config_filename, i);
        lp.emplace_back(i);
    }
    lpp::printfn("Trying to start run");
    rpc::client client(leader.get_hostname(), rpc::constants::DEFAULT_PORT - 1);
    std::vector<std::future<clmdep_msgpack::object_handle>> results;
    for(int i = 0; i < 500; i++) {
        session_id_t sid(hash_certificate(cert), current_timestamp_sid());
        logpicker_request_t lp_request{cert, lp, sid};

        try {
        //    client.call("start_run", lp_request);
	results.emplace_back(client.async_call("start_run", lp_request));
            lpp::printfn("Sent lpp request\n");

        } catch (rpc::timeout &t) {
            std::cout << t.what() << std::endl;
        }
    }
    for(auto& fut : results) {
        fut.wait();
        auto res = fut.get();
        lpp::error_out("Started logpicker run\n");

    }

    return 0;
}
