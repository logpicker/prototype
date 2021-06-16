message(STATUS "Fetching relic..")

if(TARGET relic_s)
    message(STATUS "Target relic_s already definded.")
    return()
endif()

FetchContent_MakeAvailable(relic)
