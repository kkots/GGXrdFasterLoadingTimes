# this CMakeLists.txt is for Linux compilation
cmake_minimum_required(VERSION "${MIN_VER_CMAKE}" FATAL_ERROR)
project(GGXrdFasterLoadingTimes)
set(CMAKE_CXX_STANDARD 14)
add_executable(GGXrdFasterLoadingTimes GGXrdFasterLoadingTimes.cpp)
target_compile_definitions(GGXrdFasterLoadingTimes PRIVATE "-DFOR_LINUX=\"1\"")

# compile instructions
# cd into the directory with the CMakeLists.txt
#
# cmake . -DCMAKE_BUILD_TYPE=Release ..
# make
#
# The executable named "GGXrdFasterLoadingTimes" appears in the current directory.
# To launch, use:
#
# ./GGXrdFasterLoadingTimes