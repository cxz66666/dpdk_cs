project(NETWORK_FUNCTION_SERVER)

set(APP_ADDITIONAL_SOURCES)

add_executable(nf_server ./nf.cpp ${UTILSOURCES} ${APP_ADDITIONAL_SOURCES})

target_link_libraries(nf_server ${LIBRARIES})