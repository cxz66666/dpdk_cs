project(WORKINGSET)


set(APP_ADDITIONAL_SOURCES)

add_executable(delay_workingset ./delay_main.c ${UTILSOURCES} ${APP_ADDITIONAL_SOURCES})

target_link_libraries(delay_workingset ${LIBRARIES})

add_executable(bw_workingset ./bw_main.c ${UTILSOURCES} ${APP_ADDITIONAL_SOURCES})

target_link_libraries(bw_workingset ${LIBRARIES})