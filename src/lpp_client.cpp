#include "logpicker_t.hpp"

#include "types.hpp"
#include "logpicker_t.hpp"
#include "log.hpp"
#include "cert.hpp"
#include "utils.hpp"

int main() {
    cert_t cert = read_cert_from_disk("/home/leen/Projects/TU_BS/misc/LogPicker/lpp/data/github/DER/github.com");
    hash_t hash = hash_certificate(cert);
    std::cout << "Hash: " << hash << "\n";
    std::vector<Log> logs = make_logs(1);
    log_pool_t pool;
    for(const auto& log : logs) {
        //pool.emplace_back(make_instance(log));
    }
}
