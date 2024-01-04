project(BG_BW_C2S2C)

set(SAMPLE_NAME bg_bw_c2s2c)

set(APP_ADDITIONAL_SOURCES)

add_executable(${SAMPLE_NAME} ./main.c ${UTILSOURCES} ${APP_ADDITIONAL_SOURCES})

target_link_libraries(${SAMPLE_NAME} ${LIBRARIES})