cmake_minimum_required(VERSION 3.23)
project(AdvancedFHEGPU)

set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package (fideslib REQUIRED CONFIG)

# FIDESlib configuration.

if (fideslib_FOUND)
    message (STATUS "FOUND PACKAGE FIDESlib")
    message (STATUS "FIDESlib Version: ${fideslib_VERSION}")
    message (STATUS "FIDESlib header files location: ${FIDESLIB_INCLUDE_PATH}")
    message (STATUS "FIDESlib lib files location: ${FIDESLIB_LIBRARIES_PATH}")
    message (STATUS "FIDESlib binary files location: ${FIDESLIB_BINARY_PATH}")
    message (STATUS "FIDESlib C++ compiler: ${FIDESLIB_CXX_COMPILER}")
    message (STATUS "FIDESlib compile options: ${FIDESLIB_COMPILE_OPTIONS}")
else ()
    message (FATAL_ERROR "PACKAGE FIDESlib NOT FOUND")
endif ()

set (CMAKE_CXX_COMPILER ${FIDESLIB_CXX_COMPILER})
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FIDESLIB_CXX_FLAGS}")

add_executable(AdvancedFHEGPU src/main.cpp src/CKKSController.cpp src/CKKSController.h src/Utils.h)
target_sources(AdvancedFHEGPU PRIVATE src/main.cpp)
target_link_libraries (AdvancedFHEGPU PRIVATE fideslib::fideslib)

