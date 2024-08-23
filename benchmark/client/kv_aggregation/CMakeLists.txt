project(KV_AGGREGATION_CLIENT)

set(APP_ADDITIONAL_SOURCES)

add_executable(kv_client ./main.cpp ${UTILSOURCES} ${APP_ADDITIONAL_SOURCES})

target_link_libraries(kv_client ${LIBRARIES})