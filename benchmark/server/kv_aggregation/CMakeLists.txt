project(KV_AGGREGATION_SERVER)

set(APP_ADDITIONAL_SOURCES)

add_executable(kv_server ./main.cpp ${UTILSOURCES} ${APP_ADDITIONAL_SOURCES})

target_link_libraries(kv_server ${LIBRARIES})