#ifndef LPP_CERT_HPP
#define LPP_CERT_HPP

#include <vector>
#include <iostream>
#include <fstream>
#include "types.hpp"
#include <boost/container_hash/hash.hpp>

inline cert_t read_cert_from_disk(const std::string& file_path) {
    std::ifstream instream(file_path, std::ios::in | std::ios::binary);
    return {(std::istreambuf_iterator<char>(instream)), std::istreambuf_iterator<char>()};
}

inline hash_t hash_certificate(const cert_t& cert) {
    return boost::hash_range(cert.begin(), cert.end());
}

#endif
