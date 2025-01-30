cmake_minimum_required(VERSION 3.10)

# Set the project name
project(machXplorer)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the executable
add_executable(MachXplorer
    src/analyzer.cpp
    src/main.cpp
    # ...add other source files here...
)

# Include directories
target_include_directories(MachXplorer PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    # ...add other include directories here...
)
