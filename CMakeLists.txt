cmake_minimum_required(VERSION 3.14.0)
project(LPP C CXX)

option(LPP_BUILD_TEST_BINARIES "" ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# dependencies
add_subdirectory(dependencies)

find_package(fmt REQUIRED)

option(THREADS_PREFER_PTHREAD "" ON)
option(THREADS_PREFER_PTHREAD_FLAG "" ON)
find_package(Threads REQUIRED)

option(Boost_USE_MULTITHREADED "" ON)
find_package(Boost REQUIRED COMPONENTS system thread program_options)

# lpp
set(COMPILE_OPTS
    -Wall
    -Wextra
    -pipe
    -march=native
    $<$<CONFIG:Debug>:-Og>
    $<$<CONFIG:Debug>:-g>
    $<$<CONFIG:Release>:-O3>
    $<$<CXX_COMPILER_ID:AppleClang,Clang>:-Weverything>
    $<$<CXX_COMPILER_ID:AppleClang,Clang>:-Wno-c++98-compat>
    $<$<CXX_COMPILER_ID:AppleClang,Clang>:-Wno-documentation>
    $<$<CXX_COMPILER_ID:AppleClang,Clang>:-Wno-c++98-compat-pedantic>
    $<$<CXX_COMPILER_ID:AppleClang,Clang>:-Wno-extra-semi-stmt>
    $<$<CXX_COMPILER_ID:AppleClang,Clang>:-Wno-c99-extensions>
    $<$<CXX_COMPILER_ID:AppleClang,Clang>:-Wno-reserved-id-macro>
    $<$<CXX_COMPILER_ID:AppleClang,Clang>:-Wno-documentation-unknown-command>
    $<$<CXX_COMPILER_ID:AppleClang,Clang>:-Wno-unused-variable>
    $<$<CXX_COMPILER_ID:AppleClang,Clang>:-Wno-documentation-pedantic>)

set(LINK_OPTS $<$<NOT:$<CXX_COMPILER_ID:AppleClang,Clang>>:-no-pie>)

set(COMPILE_FEATS cxx_std_17)

set(COMPILE_DEFS $<$<CONFIG:Release>:NDEBUG>
                 $<$<CONFIG:Release>:BOOST_DISABLE_ASSERTS>)

add_subdirectory(src)

if(LPP_BUILD_TEST_BINARIES)
  enable_testing()
  add_subdirectory(test ${PROJECT_BINARY_DIR}/test)
endif()
