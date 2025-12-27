cmake_minimum_required(VERSION 3.12)
project(llm_security C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(BUILD_SHARED_LIBS "Build shared library" ON)
option(BUILD_EXAMPLES "Build example programs" ON)
option(ENABLE_OPENSSL "Enable OpenSSL support" ON)

# Find required packages
if(ENABLE_OPENSSL)
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        add_definitions(-DHAVE_OPENSSL)
        message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    else()
        message(STATUS "OpenSSL not found - SHA256 disabled")
    endif()
endif()

# Core library
if(BUILD_SHARED_LIBS)
    add_library(llm_security SHARED llm_security.c)
else()
    add_library(llm_security STATIC llm_security.c)
endif()

target_include_directories(llm_security PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if(OpenSSL_FOUND)
    target_link_libraries(llm_security PUBLIC OpenSSL::Crypto)
endif()

# Platform-specific settings
if(APPLE)
    target_link_libraries(llm_security PRIVATE "-framework Mach")
elseif(UNIX AND NOT APPLE)
    target_compile_options(llm_security PRIVATE -fPIC)
endif()

# C++ wrapper (optional)
add_library(llm_security_cpp INTERFACE)
target_include_directories(llm_security_cpp INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

# Examples
if(BUILD_EXAMPLES)
    # C example
    add_executable(example_c examples/example.c)
    target_link_libraries(example_c PRIVATE llm_security)
    
    # C++ example
    add_executable(example_cpp examples/example.cpp)
    target_link_libraries(example_cpp PRIVATE llm_security llm_security_cpp)
    
    message(STATUS "Examples enabled")
endif()

# Installation
install(TARGETS llm_security
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
install(FILES llm_security.h DESTINATION include)
install(FILES llm_security.hpp DESTINATION include)

message(STATUS "LLM Security Framework configured")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Shared library: ${BUILD_SHARED_LIBS}")
message(STATUS "  Examples: ${BUILD_EXAMPLES}")
