option(BUILD_BLS_PYTHON_BINDINGS "" OFF)
option(BUILD_BLS_TESTS "" OFF)
option(BUILD_BLS_BENCHMARKS "" OFF)

message(STATUS "Fetching bls-signatures...")

FetchContent_MakeAvailable(bls-signatures)
