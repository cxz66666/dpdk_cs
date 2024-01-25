project(NETWORK_FUNCTION_CLIENT)

set(APP_ADDITIONAL_SOURCES)

add_executable(nf_client ./nf.cpp ${UTILSOURCES} ${APP_ADDITIONAL_SOURCES})

target_link_libraries(nf_client ${LIBRARIES})