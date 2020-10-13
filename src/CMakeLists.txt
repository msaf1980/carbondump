set(MAIN_TARGET ${PROJECT})

find_package(PkgConfig)

pkg_check_modules(PCAP REQUIRED libpcap)

set(MAIN_SOURCES)
set(MAIN_LIBRARIES pcap)
set(MAIN_INCLUDES "${CLI11_SOURCE_DIR}/include")

# Scan dir for standart source files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} MAIN_SOURCES)

# Add executable target
add_executable("${MAIN_TARGET}" ${MAIN_SOURCES})
target_include_directories("${MAIN_TARGET}" PRIVATE ${MAIN_INCLUDES})
target_link_libraries("${MAIN_TARGET}" ${MAIN_LIBRARIES})
install(TARGETS "${MAIN_TARGET}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
