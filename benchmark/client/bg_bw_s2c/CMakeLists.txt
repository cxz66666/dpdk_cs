project(BG_BW_S2C)

set(SAMPLE_NAME bg_bw_s2c)

set(APP_ADDITIONAL_SOURCES)

# 这主要是为了控制打流的速度，测试对目标要测的延迟基本没有影响
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")

add_executable(${SAMPLE_NAME} ./main.c ${UTILSOURCES} ${APP_ADDITIONAL_SOURCES})

target_link_libraries(${SAMPLE_NAME} ${LIBRARIES})