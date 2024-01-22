project(DAEMON)

set(APP_ADDITIONAL_SOURCES)

set(SAMPLE_NAME dpdk_daemon)

add_executable(${SAMPLE_NAME} ./dpdk_daemon.c ${UTILSOURCES} ${APP_ADDITIONAL_SOURCES})

target_link_libraries(${SAMPLE_NAME} ${LIBRARIES})
