#ifndef LPP_PRINTFN_HPP
#define LPP_PRINTFN_HPP


#include <fmt/format.h>
#include <fmt/ostream.h>
#include <iostream>
#include <utility>

namespace lpp {

    template <typename... Args> void printfn(const char* format, Args&&... args) {
        //fmt::print(std::clog, format, std::forward<Args>(args)...);
    }
}

#endif

