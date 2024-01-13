project(BG_BW_C2S)

set(APP_ADDITIONAL_SOURCES)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")

add_executable(bg_bw_c2s_delay ./delay.c ${UTILSOURCES} ${APP_ADDITIONAL_SOURCES})

target_link_libraries(bg_bw_c2s_delay ${LIBRARIES})

add_executable(bg_bw_c2s_ntp ./ntp.c ${UTILSOURCES} ${APP_ADDITIONAL_SOURCES})

target_link_libraries(bg_bw_c2s_ntp ${LIBRARIES})