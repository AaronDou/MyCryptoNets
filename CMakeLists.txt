cmake_minimum_required (VERSION 3.5.1)
  
project(CryptoNets)
set(CMAKE_CXX_STANDARD 11)

find_package(SEAL 3.5 REQUIRED)

add_executable(main main.cpp)

target_link_libraries(main SEAL::seal)