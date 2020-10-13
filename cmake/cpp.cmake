string(REGEX MATCH "Clang" CMAKE_COMPILER_IS_CLANG "${CMAKE_C_COMPILER_ID}")
string(REGEX MATCH "GNU" CMAKE_COMPILER_IS_GNU "${CMAKE_C_COMPILER_ID}")
string(REGEX MATCH "IAR" CMAKE_COMPILER_IS_IAR "${CMAKE_C_COMPILER_ID}")
string(REGEX MATCH "MSVC" CMAKE_COMPILER_IS_MSVC "${CMAKE_C_COMPILER_ID}")

if(CMAKE_COMPILER_IS_GNU)
    # some warnings we want are not available with old GCC versions note:
    # starting with CMake 2.8 we could use CMAKE_C_COMPILER_VERSION
    execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion
                    OUTPUT_VARIABLE GCC_VERSION)
    if(GCC_VERSION VERSION_GREATER 4.5 OR GCC_VERSION VERSION_EQUAL 4.5)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wlogical-op")
    endif()
    if(GCC_VERSION VERSION_GREATER 4.8 OR GCC_VERSION VERSION_EQUAL 4.8)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow")
    endif()
endif(CMAKE_COMPILER_IS_GNU)

if(CMAKE_COMPILER_IS_GNU OR CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_CXX_FLAGS
        "${CMAKE_CXX_FLAGS} -Wall -Wextra -W -Wpedantic -Wconversion -Wold-style-cast -Wwrite-strings"
    )
    set(CMAKE_C_FLAGS
        "${CMAKE_C_FLAGS} -Wall -Wextra -W -Wpedantic -Wconversion -Wdeclaration-after-statement -Wwrite-strings"
    )

    if(ASAN)
        set(CMAKE_CXX_FLAGS
            "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize=undefined")
        set(CMAKE_C_FLAGS
            "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined")
        set(CMAKE_SHARED_LINKER_FLAGS
            "${CMAKE_SHARED_LINKER_FLAGS} -lasan -lubsan")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan -lubsan")
    elseif(TSAN)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -ltsan")
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "DEBUG")
        set(DEBUGINFO ON)
        string(REGEX REPLACE "/ -O[0-9] /g" " "  _CXX_FLAGS_ ${CMAKE_CXX_FLAGS})
		set(CMAKE_CXX_FLAGS "${_CXX_FLAGS_} -O0")
		string(REGEX REPLACE "/ -O[0-9] /g" " " _C_FLAGS_ ${CMAKE_C_FLAGS})
        set(CMAKE_C_FLAGS "${_C_FLAGS_} -O0")
    endif(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "DEBUG")

    if(DEBUGINFO)
        string(FIND CMAKE_CXX_FLAGS " -g" res)
        if(res EQUAL -1)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
        endif(res EQUAL -1)
        string(FIND CMAKE_C_FLAGS " -g" res)
        if(res EQUAL -1)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
        endif(res EQUAL -1)
    endif()

    if(PROFILE)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lprofiler")
    endif()

endif(CMAKE_COMPILER_IS_GNU OR CMAKE_COMPILER_IS_CLANG)
