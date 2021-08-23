aux_source_directory(. DIR_SOCKET)
add_library(SCS STATIC ${DIR_SOCKET})
target_link_libraries(SCS PBC)
target_link_libraries(SCS GMP)
