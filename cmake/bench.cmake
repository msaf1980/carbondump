if(NOT TARGET bench)
    add_custom_target(bench)
endif()

# Add benchmark to  bench target
function(custom_add_bench targetname commandname)
    add_custom_target(
        ${targetname}
        COMMAND ${commandname}
        COMMENT "Running benchmark ${targetname}")
    add_dependencies(${targetname} ${targetname})
    add_dependencies(bench ${targetname})
endfunction()
