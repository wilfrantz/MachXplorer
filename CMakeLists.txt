cmake_minimum_required(VERSION 3.10)

# Set the project name
project(MachXplorer VERSION 1.0 LANGUAGES CXX)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Target ARM64 architecture (Apple Silicon)
set(CMAKE_OSX_ARCHITECTURES "arm64")

# Use pkg-config to find Capstone and JSONCPP
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)

# Error handling if Capstone or JSONCPP is not found
if(NOT CAPSTONE_FOUND)
	message(FATAL_ERROR "Capstone library not found! Install it using 'brew install capstone'.")
endif()

# Add the executable
add_executable(MachXplorer
	src/analyzer.cpp
	src/main.cpp
)

# Include directories
target_include_directories(MachXplorer PUBLIC
	${PROJECT_SOURCE_DIR}/include
	${CAPSTONE_INCLUDE_DIRS}/..
)

# Link Capstone and JSON libraries
target_link_directories(MachXplorer PRIVATE ${CAPSTONE_LIBRARY_DIRS} ${JSONCPP_LIBRARY_DIRS})
target_link_libraries(MachXplorer PRIVATE ${CAPSTONE_LIBRARIES} )

# Print debug info
message(STATUS "Capstone include dirs: ${CAPSTONE_INCLUDE_DIRS}")
message(STATUS "Capstone library dirs: ${CAPSTONE_LIBRARY_DIRS}")
message(STATUS "Capstone libraries: ${CAPSTONE_LIBRARIES}")
