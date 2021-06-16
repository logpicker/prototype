
#ifndef LPP_DEBUG_LOG_HPP
#define LPP_DEBUG_LOG_HPP

#include <fmt/format.h>
#include <utility>

namespace lpp {

#ifdef DEBUG_LOG
template <typename... Args> void debug_log(const char* format, Args&&... args) {
  fmt::print(format, std::forward<Args>(args)...);
#else
template <typename... Args> void debug_log(const char*, Args&&...) {

#endif
}
}

#endif
