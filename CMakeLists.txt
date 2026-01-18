cmake_minimum_required(VERSION 3.16)
project(hybrid_ids_offline LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(pcap2flows src/pcap2flows.cpp)
target_include_directories(pcap2flows PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(pcap2flows PRIVATE ${PCAP_LIBRARIES})
target_compile_options(pcap2flows PRIVATE -O2 -Wall -Wextra)

add_executable(pcap2alerts src/pcap2alerts.cpp)
target_include_directories(pcap2alerts PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(pcap2alerts PRIVATE ${PCAP_LIBRARIES})
target_compile_options(pcap2alerts PRIVATE -O2 -Wall -Wextra)