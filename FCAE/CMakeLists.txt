aux_source_directory(. DIR_FCAE)
add_library(FCAE STATIC ${DIR_FCAE})

include_directories(${PROJECT_SOURCE_DIR}/Utils)
#target_include_directories(FCAE PUBLIC ../log)

target_link_libraries(FCAE PBC)
target_link_libraries(FCAE GMP)
#target_link_libraries(FCAE PLOG)
target_link_libraries(FCAE UTILS)