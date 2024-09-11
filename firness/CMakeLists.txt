cmake_minimum_required(VERSION 3.10)

project(firness VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -frtti -fsanitize=address -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -frtti -g")


#find_package(LLVM 15 REQUIRED CONFIG)

# find_package(Clang 15 REQUIRED CONFIG)

find_package(nlohmann_json 3.2.0 REQUIRED)

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
link_directories(${LLVM_LIBRARY_DIRS})

add_subdirectory(firness)