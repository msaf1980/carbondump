set(TEST ${PROJECT})
set(SOURCES_TEST)
set(INCLUDES_TEST)

# Scan source dir for standart source files and exclude main.cpp
foreach(dir IN LISTS SUB_DIRS)
    aux_source_directory(../${dir} SOURCES_TEST)
    list(REMOVE_ITEM SOURCES_TEST "../${dir}/main.cpp")
endforeach()

# Add sources from dir set( SOURCES ../${DIR_SOURCES}/rational.cpp )

foreach(dir IN LISTS DIR_INCLUDES SUB_DIRS)
    # list(APPEND INCLUDES_TEST ../${dir})
    include_directories(../${dir})
endforeach()

include_directories(${Catch2_SOURCE_DIR}/single_include)

if(SOURCES_TEST)
    add_library(test${TEST} STATIC ${SOURCES_TEST})
    list(APPEND TEST_LIBRARIES test${TEST})
endif()

# Build tests
file(GLOB testFiles *_test.cpp)
foreach(testFile ${testFiles})
    file(RELATIVE_PATH test_file ${CMAKE_CURRENT_SOURCE_DIR} ${testFile})
    string(REGEX REPLACE "^([0-9a-zA-Z_\\-]+)_test\.c.*$" "\\1" test
                         "${test_file}")
    custom_add_test("test_${test}" "${test_file}" "${TEST_LIBRARIES}" "")
endforeach(testFile)

# foreach( t IN LISTS TESTS ) add_executable( test_${t} test_${t}.cpp )
# target_link_libraries ( test_${t} ${LIBRARIES} ) add_test( NAME test_${t}
# COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${t} ) endforeach(t)

# Build benchmarks
if(BENCH)
    set(BENCH_LIBRARIES # benchmark
    )

    if(SOURCES_TEST)
        # add_library( test${PROJECT} STATIC ${SOURCES_TEST} )
        list(APPEND BENCH_LIBRARIES test${PROJECT})
    endif(SOURCES_TEST)

    file(GLOB testFiles *_bench.cpp)
    foreach(testFile ${testFiles})
        file(RELATIVE_PATH test_file ${CMAKE_CURRENT_SOURCE_DIR} ${testFile})
        string(REGEX REPLACE "^([0-9a-zA-Z_\\-]+)_bench\.c.*$" "\\1" test
                             "${test_file}")
        add_executable(bench_${test} ${test_file} ${SOURCES_TEST})
        target_link_libraries(bench_${test} ${BENCH_LIBRARIES})
        add_bench(bench_${test} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/bench_${test})
    endforeach(testFile)
endif(BENCH)

# add_test( NAME test_output COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_run.sh
# ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${MAIN_BINARY}
# ${CMAKE_CURRENT_SOURCE_DIR}/out )

# add_test( NAME test_cmd COMMAND test_cmd ${CMAKE_CURRENT_SOURCE_DIR}/out
# ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${BINARY} )
