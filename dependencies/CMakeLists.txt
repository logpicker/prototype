include(FetchContent)

# ==========================================================
FetchContent_Declare(
  bls-signatures
  GIT_REPOSITORY https://github.com/logpicker/bls-signatures.git
  GIT_TAG origin/master)

FetchContent_Declare(
  relic
  GIT_REPOSITORY https://github.com/relic-toolkit/relic.git
  GIT_TAG 1885ae3b681c423c72b65ce1fe70910142cf941c)

FetchContent_Declare(
  rpclib
  GIT_REPOSITORY https://github.com/qchateau/rpclib.git
  GIT_TAG 5b26d69f2aefd0a4a731cba43f9fd4fcf9ded949)
# ==========================================================

# bls-signatures
option(BUILD_BLS_PYTHON_BINDINGS "" OFF)
option(BUILD_BLS_TESTS "" OFF)
option(BUILD_BLS_BENCHMARKS "" OFF)

# relic
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    option(DEBUG "Relic debug build" ON)
endif()

set(BN_PRECI 2048 CACHE STRING "")

# rpclib
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    option(RPCLIB_ENABLE_LOGGING "" ON)
endif()

add_subdirectory(bls-signatures)
add_subdirectory(relic)
add_subdirectory(rpclib)
