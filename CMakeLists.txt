cmake_minimum_required (VERSION 3.5.1)
  
project(MyCryptoNets)
set(CMAKE_CXX_STANDARD 14)

# find_package(SEAL 3.2.1 REQUIRED)
find_package(SEAL 3.5 REQUIRED)
find_package(OpenMP)

################################
# Core lib
################################
file(GLOB libfiles "include/*.h" "include/*.cpp")
add_library(core ${libfiles})
target_link_libraries(core PUBLIC SEAL::seal)
if(OpenMP_CXX_FOUND)
    target_link_libraries(core PUBLIC OpenMP::OpenMP_CXX)
endif()

################################
# Main app
################################
file(GLOB cryptonets_files "apps/cryptonets/*.h" "apps/cryptonets/*.cpp")
add_executable(cryptonets ${cryptonets_files})
target_link_libraries(cryptonets PUBLIC core)
target_include_directories(cryptonets
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
)


################################
# GTest
################################
add_subdirectory(third-party/googletest)
enable_testing()
include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})


################################
# Unit Test wrapper_test
################################
add_executable(wrapper_test test/SealBfvCrtWrapperTest.cpp)
target_link_libraries(wrapper_test gtest_main core)
target_include_directories(wrapper_test
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
)

################################
# Unit Test vector_test
################################
add_executable(vector_test test/SealBfvVectorTest.cpp)
target_link_libraries(vector_test gtest_main core)
target_include_directories(vector_test
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
)

################################
# Unit Test nn_test
################################
add_executable(nn_test test/NeuralNetworksTest.cpp)
target_link_libraries(nn_test gtest_main core)
target_include_directories(nn_test
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
)

################################
# Unit Test seal_benchmark
################################
add_executable(seal_benchmark test/SealBenchmark.cpp)
target_link_libraries(seal_benchmark gtest_main core)
target_include_directories(seal_benchmark
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
)

################################
# Unit Test LL_nn_test
################################
add_executable(LL_nn_test test/LLNeuralNetworksTest.cpp)
target_link_libraries(LL_nn_test gtest_main core)
target_include_directories(LL_nn_test
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
)

