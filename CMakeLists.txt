cmake_minimum_required (VERSION 3.5.1)
  
project(CryptoNets)
set(CMAKE_CXX_STANDARD 14)

find_package(SEAL 3.5 REQUIRED)
find_package(xtensor REQUIRED)
find_package(xtl REQUIRED)
find_package(Torch REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${TORCH_CXX_FLAGS}")

add_executable(main main.cpp)
target_link_libraries(main PUBLIC SEAL::seal "${TORCH_LIBRARIES}")