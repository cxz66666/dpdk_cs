project(DELAY_TWO_THREAD)

set(SAMPLE_NAME delay_two_thread)

set(APP_ADDITIONAL_SOURCES)

add_executable(${SAMPLE_NAME} ./main.c ${UTILSOURCES} ${APP_ADDITIONAL_SOURCES})

target_link_libraries(${SAMPLE_NAME} ${LIBRARIES})