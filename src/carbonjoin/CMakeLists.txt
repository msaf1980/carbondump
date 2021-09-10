set(JOIN_TARGET carbonjoin)

find_package(PkgConfig)

set(JOIN_SOURCES)
set(JOIN_LIBRARIES strutils_static)
set(JOIN_INCLUDES "${CLI11_SOURCE_DIR}/include" "${strutils_SOURCE_DIR}/include")

# Scan dir for standart source files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} JOIN_SOURCES)

# Add executable target
add_executable("${JOIN_TARGET}" ${JOIN_SOURCES})
target_include_directories("${JOIN_TARGET}" PRIVATE ${JOIN_INCLUDES})
target_link_libraries("${JOIN_TARGET}" ${JOIN_LIBRARIES})
install(TARGETS "${JOIN_TARGET}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
