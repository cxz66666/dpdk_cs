project(L2FWD_WORKINGSET)

set(SAMPLE_NAME l2fwd_workingset)

set(APP_ADDITIONAL_SOURCES)
add_executable(${SAMPLE_NAME} ./main.c ${UTILSOURCES} ${APP_ADDITIONAL_SOURCES})

target_link_libraries(${SAMPLE_NAME} ${LIBRARIES})