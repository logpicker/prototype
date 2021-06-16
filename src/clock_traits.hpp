#ifndef CLOCK_TRAITS_HPP
#define CLOCK_TRAITS_HPP

#include <chrono>
#include <type_traits>
#include <string>

struct clock_traits {
  using clock_type_t = std::conditional_t<std::chrono::high_resolution_clock::is_steady,
                                        std::chrono::high_resolution_clock, std::chrono::steady_clock>;
  // Some gcc versions used to not comply with this..
  static_assert(clock_type_t::is_steady, "No steady clock available..");
  using time_unit = std::chrono::milliseconds;
  static constexpr auto suffix = "ms";
};

inline int64_t current_timestamp() {
    auto tp = clock_traits::clock_type_t::now();
    auto ts = std::chrono::duration_cast<clock_traits::time_unit>(tp.time_since_epoch());
    return ts.count();
}

inline int64_t current_timestamp_sid() {
    auto tp = clock_traits::clock_type_t::now();
    auto ts = std::chrono::duration_cast<std::chrono::nanoseconds>(tp.time_since_epoch());
    return ts.count();
}
#endif
