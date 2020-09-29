cmake_minimum_required (VERSION 3.5.1)
  
project(MyCryptoNets)
set(CMAKE_CXX_STANDARD 14)

find_package(SEAL 3.5 REQUIRED)
find_package(OpenMP)

add_library(core include/core.h include/util.h)
target_link_libraries(core PUBLIC SEAL::seal)
if(OpenMP_CXX_FOUND)
    target_link_libraries(core PUBLIC OpenMP::OpenMP_CXX)
endif()


add_executable(main main.cpp)
target_link_libraries(main PUBLIC core)
target_include_directories(main
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
)


add_executable(libtest test/tests.cpp)
target_link_libraries(libtest gtest_main core)
target_include_directories(libtest
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
)
