add_executable (test_rsa_util test_rsa_util.c)

target_link_libraries(test_rsa_util logpicker)
target_compile_options(test_rsa_util PRIVATE ${COMPILE_OPTS})
target_link_options(test_rsa_util PRIVATE ${LINK_OPTS})
target_compile_features(test_rsa_util PRIVATE ${COMPILE_FEATS})
target_compile_definitions(test_rsa_util PRIVATE ${COMPILE_DEFS})

add_test(test_rsa_util test_rsa_util)

add_executable(test_crypto test_crypto.cpp)

target_link_libraries(test_crypto logpicker)
target_compile_options(test_crypto PRIVATE ${COMPILE_OPTS})
target_link_options(test_crypto PRIVATE ${LINK_OPTS})
target_compile_features(test_crypto PRIVATE ${COMPILE_FEATS})
target_compile_definitions(test_crypto PRIVATE ${COMPILE_DEFS})

add_test(test_crypto test_crypto)

add_executable(test_lpp_local test_lpp_local.cpp)

target_link_libraries(test_lpp_local logpicker)
target_compile_options(test_lpp_local PRIVATE ${COMPILE_OPTS})
target_link_options(test_lpp_local PRIVATE ${LINK_OPTS})
target_compile_features(test_lpp_local PRIVATE ${COMPILE_FEATS})
target_compile_definitions(test_lpp_local PRIVATE ${COMPILE_DEFS})

add_test(NAME test_lpp_local
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMAND build/test/test_lpp_local data/config.xml data/github/DER/github.com)

