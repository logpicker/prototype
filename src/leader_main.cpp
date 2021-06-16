#include "leader.h"
#include "log.hpp"
#include "logpicker_leader.h"
#include <rpc/client.h>
#include "rpc/server.h"
#include "error_out.hpp"
#include "utils.hpp"


int main(int argc, char **argv) {
    std::string cfg = argv[1];
    //std::string cfg = "/home/i1000666/lpp/data/config.xml";
    Log l = Log::read_leader(cfg);
    log_map_t pool = read_log_pool(cfg);
    boost::asio::io_context ios;
    leader_t leader(ios, l, pool);
    auto port = rpc::constants::DEFAULT_PORT - 1;
    lpp::printfn("Starting leader instance {} on port: {}\n", l.get_id(), port);
    rpc::server srv("0.0.0.0", port);

    srv.bind("start_run", [&leader](const logpicker_request_t& req){ leader.start_run(req); return true;});
    lpp::printfn("Starting leader \n");
    srv.suppress_exceptions(false);
    srv.async_run(64);
    leader.run(32);
    ios.run();
    std::cin.ignore();
    return 0;
}