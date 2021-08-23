aux_source_directory(. DIR_KGC)
add_library(KGC STATIC ${DIR_KGC})
include_directories(../Socket)
include_directories(../Utils)
include_directories(../FCAE)
target_include_directories(KGC PUBLIC ../log)
target_link_libraries(KGC PBC)
target_link_libraries(KGC GMP)
target_link_libraries(KGC SCS)
target_link_libraries(KGC PLOG)
target_link_libraries(KGC UTILS)
target_link_libraries(KGC FCAE)


