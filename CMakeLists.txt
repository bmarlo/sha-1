cmake_minimum_required(VERSION 3.10)

project(sha-1)

function(cpp17 target)
    set_target_properties(${target}
        PROPERTIES
            CXX_STANDARD 17
            CXX_STANDARD_REQUIRED ON
            CXX_EXTENSIONS OFF
    )

    target_compile_options(${target}
        PRIVATE
            -Wall -Wextra -Wconversion -pedantic -Wno-sign-conversion
    )
endfunction()

add_library(sha1 STATIC src/sha1.cpp)
cpp17(sha1)
target_include_directories(sha1 PUBLIC include)

add_executable(sha1sum examples/sha1sum.cpp)
cpp17(sha1sum)
target_link_libraries(sha1sum sha1)
