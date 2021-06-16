#ifndef LPP_ERROR_OUT_HPP
#define LPP_ERROR_OUT_HPP


#include <fmt/format.h>
#include <fmt/ostream.h>
#include <iostream>
#include <utility>

namespace lpp {

    template <typename... Args> void error_out(const char* format, Args&&... args) {
        fmt::print(std::cerr, format, std::forward<Args>(args)...);
    }
}

#endif

