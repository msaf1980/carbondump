# Add executable target
function(custom_add_executable TARGET SOURCES LIBRARIES INCLUDES INSTALL)
    add_executable(${TARGET} ${SOURCES})
    if(INCLUDES)
        target_include_directories(${TARGET} PRIVATE ${INCLUDES})
    endif(INCLUDES)
    if(LIBRARIES)
        target_link_libraries(${TARGET} ${LIBRARIES})
    endif(LIBRARIES)
    if(INSTALL)
        install(TARGETS ${TARGET} DESTINATION ${INSTALL})
    endif(INSTALL)
endfunction()

# Add library
function(
    custom_add_library
    TARGET
    SOURCES
    LIBRARIES
    INCLUDES
    INSTALL
    VERSION_MAJOR
    VERSION_MINOR)
    add_library(${TARGET} ${SOURCES})
    if(INCLUDES)
        target_include_directories(${TARGET} PRIVATE ${INCLUDES})
    endif(INCLUDES)
    if(LIBRARIES)
        target_link_libraries(${TARGET} ${LIBRARIES})
    endif(LIBRARIES)
    if(VERSION_MAJOR)
        if(VERSION_MINOR)
            set("${VERSION}" "${VERSION_MAJOR}.${VERSION_MINOR}")
        else(VERSION_MINOR)
            set("${VERSION}" "${VERSION_MAJOR}")
        endif(VERSION_MINOR)
        set_target_properties(${TARGET} PROPERTIES VERSION "${VERSION}"
                                                   SOVERSION "${VERSION_MAJOR}")
    endif(VERSION_MAJOR)
    if(INSTALL)
        install(TARGETS ${TARGET} DESTINATION ${INSTALL})
    endif(INSTALL)
endfunction()

# Add test target
function(custom_add_test TARGET SOURCES LIBRARIES INCLUDES)
    custom_add_executable("${TARGET}" "${SOURCES}" "${LIBRARIES}" "${INCLUDES}"
                          "")
    add_test(NAME "${TARGET}"
             COMMAND "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TARGET}")
endfunction()
