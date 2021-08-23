aux_source_directory(. DIR_UTILS)
add_library(UTILS STATIC ${DIR_UTILS})
#target_link_libraries(UTILS Cryptopp)
target_include_directories(UTILS PUBLIC ${PROJECT_SOURCE_DIR}/openssl/include)

target_link_libraries(UTILS Crypto)
target_link_libraries(UTILS pthread)
target_link_libraries(UTILS dl)

