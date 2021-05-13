include_directories(${ROOT_DIR}/Inc)

add_library(ip_filter STATIC ip_filter.cpp)
add_executable(cin_filter.out main.cpp)

target_link_libraries(cin_filter.out ip_filter)

install(TARGETS ip_filter DESTINATION ${ROOT_DIR}/lib)
install(TARGETS cin_filter.out DESTINATION ${ROOT_DIR}/bin)