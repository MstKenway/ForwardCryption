cmake_minimum_required(VERSION 3.10)
project(Auth_All)

set(CMAKE_CXX_STANDARD 11)


SET(CMAKE_BUILD_TYPE DEBUG)


add_library(PBC STATIC IMPORTED GLOBAL)
add_library(GMP STATIC IMPORTED GLOBAL)
add_library(Crypto STATIC IMPORTED GLOBAL)
add_library(SSL STATIC IMPORTED GLOBAL)


IF (WIN32)
    message(WIN32)
    set_target_properties(
            PBC
            PROPERTIES IMPORTED_LOCATION
            ${PROJECT_SOURCE_DIR}/pbc/lib_win/libpbc.a
    )
    set_target_properties(
            GMP
            PROPERTIES IMPORTED_LOCATION
            ${PROJECT_SOURCE_DIR}/pbc/lib_mac/libgmp.a
    )
elseif (APPLE)
    message(APPLE)
    set_target_properties(
            PBC
            PROPERTIES IMPORTED_LOCATION
            ${PROJECT_SOURCE_DIR}/pbc/lib_mac/libpbc.a
    )
    set_target_properties(
            GMP
            PROPERTIES IMPORTED_LOCATION
            ${PROJECT_SOURCE_DIR}/pbc/lib_mac/libgmp.a
    )
    set_target_properties(
            Crypto
            PROPERTIES IMPORTED_LOCATION
            ${PROJECT_SOURCE_DIR}/openssl/lib_mac/libcrypto.a
    )
    set_target_properties(
            SSL
            PROPERTIES IMPORTED_LOCATION
            ${PROJECT_SOURCE_DIR}/openssl/lib_mac/libssl.a
    )
elseif (UNIX AND ${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
    message(RASPBERRY)
    set_target_properties(
            PBC
            PROPERTIES IMPORTED_LOCATION
            ${PROJECT_SOURCE_DIR}/pbc/lib_rb/libpbc.a
    )
    set_target_properties(
            GMP
            PROPERTIES IMPORTED_LOCATION
            ${PROJECT_SOURCE_DIR}/pbc/lib_rb/libgmp.a
    )
else ()
    message(LINUX)
    set_target_properties(
            PBC
            PROPERTIES IMPORTED_LOCATION
            ${PROJECT_SOURCE_DIR}/pbc/lib_linux/libpbc.a
    )
    set_target_properties(
            GMP
            PROPERTIES IMPORTED_LOCATION
            ${PROJECT_SOURCE_DIR}/pbc/lib_linux/libgmp.a
    )
    set_target_properties(
            Crypto
            PROPERTIES IMPORTED_LOCATION
            ${PROJECT_SOURCE_DIR}/openssl/lib/libcrypto.a
    )
    set_target_properties(
            SSL
            PROPERTIES IMPORTED_LOCATION
            ${PROJECT_SOURCE_DIR}/openssl/lib/libssl.a
    )
endif ()
set_target_properties(
        PBC
        PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
        ${PROJECT_SOURCE_DIR}/pbc/include/pbc
)
set_target_properties(
        GMP
        PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
        ${PROJECT_SOURCE_DIR}/pbc/include
)
set_target_properties(
        Crypto
        PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
        ${PROJECT_SOURCE_DIR}/openssl/include
)
set_target_properties(
        SSL
        PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
        ${PROJECT_SOURCE_DIR}/openssl/include
)

add_subdirectory(FCAE)
add_subdirectory(KGC)
add_subdirectory(Socket)
add_subdirectory(log)
add_subdirectory(Utils)

include_directories(Socket)
include_directories(${PROJECT_SOURCE_DIR}/openssl/include)

add_executable(Auth_KGC KGC_MAIN.cpp)
add_executable(Auth_TEST main.cpp)
add_executable(Auth_PARAM PBC_PARAM_MAIN.cpp)

target_link_libraries(Auth_TEST UTILS)
target_link_libraries(Auth_TEST KGC)
target_link_libraries(Auth_TEST FCAE)


target_link_libraries(Auth_PARAM PBC GMP UTILS)

target_link_libraries(Auth_KGC KGC)

