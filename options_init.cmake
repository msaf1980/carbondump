option(TEST      "Build tests" ON)
option(BENCH     "Build benchmarks" OFF)
option(ASAN      "Adds sanitize flags" OFF)
option(TSAN      "Adds thread sanitize flags" OFF)
option(PROFILE   "Enable profiling with gperftools" OFF)
option(DEBUGINFO "Add debug info" OFF)

if(ASAN)
	set(TSANITIZE OFF)
endif()

if(BENCH)
	set(TEST ON)
endif()

#include(GNUInstallDirs)

set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set ( DEP_INSTALL_DIR ${CMAKE_BINARY_DIR}/external )
set ( DEP_SOURCE_DIR ${CMAKE_BINARY_DIR}/external/src )
if (NOT EXISTS ${DEP_INSTALL_DIR} )
	file( MAKE_DIRECTORY ${DEP_INSTALL_DIR} )
endif()
