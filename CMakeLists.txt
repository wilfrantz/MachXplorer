cmake_minimum_required(VERSION 3.10)

# Set the project name
project(machXplorer VERSION 1.0 LANGUAGES CXX)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Set the target architecture
set(CMAKE_OSX_ARCHITECTURES "arm64")

# Set the path to the Capstone library
set(Capstone_DIR "/opt/homebrew/Cellar/capstone/5.0.3/lib/cmake/capstone")

# Find the Capstone library
# find_package(Capstone REQUIRED)

# Add the executable
add_executable(MachXplorer
    src/analyzer.cpp
    src/main.cpp
    # ...add other source files here...
)

# Include directories
target_include_directories(MachXplorer PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${CAPSTONE_INCLUDE_DIRS}
    # ...add other include directories here...
)

# Link with Capstone library
target_link_libraries(MachXplorer PRIVATE ${CAPSTONE_LIBRARIES})
