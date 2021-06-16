include(FetchContent)

FetchContent_GetProperties(relic)
FetchContent_GetProperties(bls-signatures)
FetchContent_GetProperties(rpclib)

set(INCLUDES
    ${PROJECT_SOURCE_DIR}/src
    ${relic_SOURCE_DIR}/include
    ${relic_BINARY_DIR}/include
    ${GMP_INCLUDES}
    ${bls-signatures_SOURCE_DIR}/src
    ${rpc_SOURCE_DIR}/include
    ${Boost_INCLUDE_DIR})

set(LIBS
    bls
    relic_s
    ${sodium_LIBRARY_RELEASE}
    rpc
    Threads::Threads
    fmt::fmt
    ${Boost_LIBRARIES})

add_library(
  logpicker OBJECT
  logpicker_t.hpp
  leader.cpp
  crypto.cpp
  logpicker_state.hpp
  logpicker_messages.cpp
  logpicker_messages.hpp
  logpicker_messages.cpp
  cert.hpp
  utils.hpp
  logpicker_instance.cpp
  types.hpp
  logpicker_instance.hpp
  logpicker_leader.cpp
  logpicker_leader.h
  debug_log.hpp
  printfn.hpp
  error_out.hpp
  log.cpp
  leader_instance.cpp
  leader_instance.h
  rsa_util.c)

target_include_directories(logpicker PUBLIC ${INCLUDES})
target_link_libraries(logpicker ${LIBS})
target_compile_options(logpicker PRIVATE ${COMPILE_OPTS})
target_link_options(logpicker PRIVATE ${LINK_OPTS})
target_compile_features(logpicker PRIVATE ${COMPILE_FEATS})
target_compile_definitions(logpicker PRIVATE ${COMPILE_DEFS})

add_executable(lpp EXCLUDE_FROM_ALL lpp.cpp)
target_link_libraries(lpp logpicker)
target_compile_options(lpp PRIVATE ${COMPILE_OPTS})
target_link_options(lpp PRIVATE ${LINK_OPTS})
target_compile_features(lpp PRIVATE ${COMPILE_FEATS})
target_compile_definitions(lpp PRIVATE ${COMPILE_DEFS})

add_executable(client client.cpp)
target_link_libraries(client logpicker)
target_compile_options(client PRIVATE ${COMPILE_OPTS})
target_link_options(client PRIVATE ${LINK_OPTS})
target_compile_features(client PRIVATE ${COMPILE_FEATS})
target_compile_definitions(client PRIVATE ${COMPILE_DEFS})

add_executable(log server.cpp)
target_link_libraries(log logpicker)
target_compile_options(log PRIVATE ${COMPILE_OPTS})
target_link_options(log PRIVATE ${LINK_OPTS})
target_compile_features(log PRIVATE ${COMPILE_FEATS})
target_compile_definitions(log PRIVATE ${COMPILE_DEFS})


add_executable(leader leader_main.cpp)
target_link_libraries(leader logpicker)
target_compile_options(leader PRIVATE ${COMPILE_OPTS})
target_link_options(leader PRIVATE ${LINK_OPTS})
target_compile_features(leader PRIVATE ${COMPILE_FEATS})
target_compile_definitions(leader PRIVATE ${COMPILE_DEFS})

add_executable(leader_local EXCLUDE_FROM_ALL leader_local.cpp)
target_link_libraries(leader_local logpicker)
target_compile_options(leader_local PRIVATE ${COMPILE_OPTS})
target_link_options(leader_local PRIVATE ${LINK_OPTS})
target_compile_features(leader_local PRIVATE ${COMPILE_FEATS})
target_compile_definitions(leader_local PRIVATE ${COMPILE_DEFS})

set_target_properties(
  logpicker
  lpp
  client
  log
  leader
  leader_local
  PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib"
             LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib"
             RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")
