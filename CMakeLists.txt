cmake_minimum_required (VERSION 3.5.1)
  
project(MyCryptoNets)
set(CMAKE_CXX_STANDARD 14)

find_package(SEAL 3.2.1 REQUIRED)
find_package(OpenMP)


file(GLOB libfiles "include/*.h" "include/*.cpp")
add_library(core ${libfiles})
target_link_libraries(core PUBLIC SEAL::seal)
if(OpenMP_CXX_FOUND)
    target_link_libraries(core PUBLIC OpenMP::OpenMP_CXX)
endif()

file(GLOB cryptonets_files "apps/cryptonets/*.h" "apps/cryptonets/*.cpp")
add_executable(cryptonets ${cryptonets_files})
target_link_libraries(cryptonets PUBLIC core)
target_include_directories(cryptonets
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
)


add_executable(wrapper_test test/SealBfvCrtWrapperTest.cpp)
target_link_libraries(wrapper_test gtest_main core)
target_include_directories(wrapper_test
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
)

add_executable(vector_test test/SealBfvVectorTest.cpp)
target_link_libraries(vector_test gtest_main core)
target_include_directories(vector_test
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
)

add_executable(nn_test test/NeuralNetworksTest.cpp)
target_link_libraries(nn_test gtest_main core)
target_include_directories(nn_test
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
)

add_executable(seal_benchmark test/SealBenchmark.cpp)
target_link_libraries(seal_benchmark gtest_main core)
target_include_directories(seal_benchmark
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
)
