cmake_minimum_required(VERSION 3.16)
project(igmpshark VERSION 0.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run)

option(IGMPSHARK_WITH_WIRESHARK "Build the igmpshark executable against libwireshark 4.2.6" ON)

find_package(PkgConfig REQUIRED)

add_library(igmpcore STATIC
    src/igmp_parse.c
    src/engine.c
    src/reconcile.c
    src/backend.c
    src/pods.c
    src/coord.c
    src/runtime.c
    src/query.c)
target_include_directories(igmpcore PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_compile_options(igmpcore PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_compile_definitions(igmpcore PRIVATE _GNU_SOURCE)

function(igmp_test name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE igmpcore)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wno-unused-parameter)
    target_compile_definitions(${name} PRIVATE _GNU_SOURCE)
endfunction()

igmp_test(test_igmp tests/test_igmp.c)
igmp_test(test_runtime tests/test_runtime.c)

enable_testing()
add_test(NAME test_igmp COMMAND test_igmp)
add_test(NAME test_runtime COMMAND test_runtime)

if(IGMPSHARK_WITH_WIRESHARK)
    set(WIRESHARK_ROOT "" CACHE PATH "Wireshark 4.2.6 source tree")
    set(WIRESHARK_LIBRARY_DIR "" CACHE PATH "Directory containing libwireshark.so")
    pkg_check_modules(GLIB REQUIRED glib-2.0)
    pkg_check_modules(PCAP REQUIRED libpcap)
    pkg_check_modules(CURL REQUIRED libcurl)
    find_path(WS_INCLUDE epan/epan.h HINTS ${WIRESHARK_ROOT} PATH_SUFFIXES include)
    find_path(WS_PUBLIC wireshark.h HINTS ${WIRESHARK_ROOT}/include ${WS_INCLUDE})
    find_library(WS_WIRESHARK wireshark HINTS ${WIRESHARK_LIBRARY_DIR} ${WIRESHARK_ROOT}/build/run)
    find_library(WS_WIRETAP wiretap HINTS ${WIRESHARK_LIBRARY_DIR} ${WIRESHARK_ROOT}/build/run)
    find_library(WS_WSUTIL wsutil HINTS ${WIRESHARK_LIBRARY_DIR} ${WIRESHARK_ROOT}/build/run)
    if(NOT WS_INCLUDE OR NOT WS_WIRESHARK)
        message(FATAL_ERROR "Wireshark 4.2.6 not found. Set WIRESHARK_ROOT or pass -DIGMPSHARK_WITH_WIRESHARK=OFF")
    endif()
    if(EXISTS "${WS_INCLUDE}/ws_version.h.in")
        file(READ "${WS_INCLUDE}/CMakeLists.txt" ws_project)
        if(NOT ws_project MATCHES "set\\(PROJECT_MAJOR_VERSION 4\\)" OR
           NOT ws_project MATCHES "set\\(PROJECT_MINOR_VERSION 2\\)" OR
           NOT ws_project MATCHES "set\\(PROJECT_PATCH_VERSION 6\\)")
            message(FATAL_ERROR "WIRESHARK_ROOT is not Wireshark 4.2.6")
        endif()
        set(PROJECT_MAJOR_VERSION 4)
        set(PROJECT_MINOR_VERSION 2)
        set(PROJECT_PATCH_VERSION 6)
        configure_file("${WS_INCLUDE}/ws_version.h.in" "${CMAKE_BINARY_DIR}/ws_version.h" @ONLY)
    endif()

    add_executable(igmpshark src/main.c src/ws_capture.c src/kube.c)
    target_link_libraries(igmpshark PRIVATE igmpcore
        ${WS_WIRESHARK} ${WS_WIRETAP} ${WS_WSUTIL}
        ${GLIB_LIBRARIES} ${PCAP_LIBRARIES} ${CURL_LIBRARIES} pthread)
    target_include_directories(igmpshark PRIVATE
        ${CMAKE_BINARY_DIR} ${WS_INCLUDE} ${WS_PUBLIC} ${GLIB_INCLUDE_DIRS} ${PCAP_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS})
    target_compile_options(igmpshark PRIVATE -Wall -Wextra -Wno-unused-parameter)
    target_compile_definitions(igmpshark PRIVATE _GNU_SOURCE)
    if(WIRESHARK_ROOT)
        set_target_properties(igmpshark PROPERTIES
            BUILD_RPATH "${WIRESHARK_ROOT}/build/run"
            INSTALL_RPATH "${WIRESHARK_ROOT}/build/run")
    endif()

    add_executable(test_ws tests/test_ws.c src/ws_capture.c)
    target_link_libraries(test_ws PRIVATE igmpcore ${WS_WIRESHARK} ${WS_WIRETAP} ${WS_WSUTIL}
        ${GLIB_LIBRARIES} ${PCAP_LIBRARIES})
    target_include_directories(test_ws PRIVATE
        ${CMAKE_BINARY_DIR} ${WS_INCLUDE} ${WS_PUBLIC} ${GLIB_INCLUDE_DIRS} ${PCAP_INCLUDE_DIRS})
    target_compile_options(test_ws PRIVATE -Wall -Wextra -Wno-unused-parameter)
    target_compile_definitions(test_ws PRIVATE _GNU_SOURCE)
    if(WIRESHARK_ROOT)
        set_target_properties(test_ws PROPERTIES BUILD_RPATH "${WIRESHARK_ROOT}/build/run")
    endif()
    add_test(NAME test_ws COMMAND test_ws
        ${CMAKE_SOURCE_DIR}/tests/fixtures/igmp.pcap
        ${CMAKE_SOURCE_DIR}/tests/fixtures/igmp.pcapng)
endif()
