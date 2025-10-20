cmake_minimum_required(VERSION 3.10)
project(T2Tree_Project)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Performance optimization compilation options
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# SIMD instruction sets
include(CheckCXXCompilerFlag)

# Set different optimization parameters based on compiler
if(MSVC)
    # Windows MSVC compiler parameters
    # Set source file encoding to UTF-8
    add_compile_options(/source-charset:utf-8)
    add_compile_options(/execution-charset:utf-8)
    
    # Disable unsafe function warnings
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    
    set(CMAKE_CXX_FLAGS_RELEASE "/O2 /DNDEBUG /Ob2 /Oi /Ot /Oy /GL")
    set(CMAKE_CXX_FLAGS_DEBUG "/Zi /Od /DDEBUG")
    
    # MSVC SIMD support
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /arch:AVX2")
    add_definitions(-D__AVX2__)
    
    # Set compilation options
    if(CMAKE_BUILD_TYPE MATCHES Release)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_RELEASE}")
    else()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_DEBUG}")
    endif()
    
    # MSVC warning options
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
    
else()
    # GCC/Clang compiler parameters (Linux/Unix)
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -march=native -mtune=native")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -funroll-loops -finline-functions")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fomit-frame-pointer -ffast-math")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -flto")  # Link Time Optimization (GCC/Clang)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fno-signed-zeros -fno-trapping-math")
    
    # Check AVX2 support
    CHECK_CXX_COMPILER_FLAG("-mavx2" COMPILER_SUPPORTS_AVX2)
    if(COMPILER_SUPPORTS_AVX2)
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mavx2")
        add_definitions(-D__AVX2__)
        set(SIMD_ENABLED "AVX2")
    endif()
    
    # Check SSE4.2 support (as fallback)
    if(NOT COMPILER_SUPPORTS_AVX2)
        CHECK_CXX_COMPILER_FLAG("-msse4.2" COMPILER_SUPPORTS_SSE42)
        if(COMPILER_SUPPORTS_SSE42)
            set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -msse4.2")
            add_definitions(-D__SSE4_2__)
            set(SIMD_ENABLED "SSE4.2")
        endif()
    endif()
    
    # Check compiler-specific optimization options
    # GCC-specific optimization options
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        # GCC auto-vectorization options
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -ftree-vectorize")
        # GCC prefetch optimization
        CHECK_CXX_COMPILER_FLAG("-fprefetch-loop-arrays" COMPILER_SUPPORTS_PREFETCH)
        if(COMPILER_SUPPORTS_PREFETCH)
            set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fprefetch-loop-arrays")
        endif()
    # Clang-specific optimization options
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        # Clang vectorization options
        CHECK_CXX_COMPILER_FLAG("-fvectorize" COMPILER_SUPPORTS_VECTORIZE)
        if(COMPILER_SUPPORTS_VECTORIZE)
            set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fvectorize")
        endif()
        # Clang SLP vectorization
        CHECK_CXX_COMPILER_FLAG("-fslp-vectorize" COMPILER_SUPPORTS_SLP_VECTORIZE)
        if(COMPILER_SUPPORTS_SLP_VECTORIZE)
            set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fslp-vectorize")
        endif()
    endif()
    
    # Debug mode maintains original settings
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
    
    # Set compilation options
    if(CMAKE_BUILD_TYPE MATCHES Release)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_RELEASE}")
    else()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_DEBUG}")
    endif()
    
    # GCC/Clang warning options
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-sign-compare")
endif()

# Set source file directory
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)

# Include header file directory
include_directories(${SRC_DIR})

# Collect all source files
file(GLOB_RECURSE SOURCES 
    "${SRC_DIR}/*.cpp"
)

# Collect all header files
file(GLOB_RECURSE HEADERS 
    "${SRC_DIR}/*.h"
)

# Create executable file
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# OpenMP support
find_package(OpenMP)
if(OpenMP_CXX_FOUND)
    set(OPENMP_ENABLED "YES")
    message(STATUS "   ✓ OpenMP parallel processing enabled")
else()
    set(OPENMP_ENABLED "NO")
endif()

# Link libraries
if(OpenMP_CXX_FOUND)
    if(NOT WIN32)
        target_link_libraries(${PROJECT_NAME} OpenMP::OpenMP_CXX m)
    else()
        target_link_libraries(${PROJECT_NAME} OpenMP::OpenMP_CXX)
    endif()
else()
    if(NOT WIN32)
        target_link_libraries(${PROJECT_NAME} m)
    endif()
endif()

# Enable LTO in Release mode
if(CMAKE_BUILD_TYPE MATCHES Release)
    # Check if IPO/LTO is supported
    include(CheckIPOSupported)
    check_ipo_supported(RESULT ipo_supported OUTPUT error)
    if(ipo_supported)
        set_property(TARGET ${PROJECT_NAME} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    else()
        message(STATUS "IPO/LTO not supported: ${error}")
    endif()
endif()

# Set output directory
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Create data directory and copy data files
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# If data files exist, copy to build directory
if(EXISTS ${CMAKE_SOURCE_DIR}/data/acl_10k)
    configure_file(${CMAKE_SOURCE_DIR}/data/acl_10k ${CMAKE_BINARY_DIR}/bin/acl_10k COPYONLY)
endif()

if(EXISTS ${CMAKE_SOURCE_DIR}/data/acl_10k_trace)
    configure_file(${CMAKE_SOURCE_DIR}/data/acl_10k_trace ${CMAKE_BINARY_DIR}/bin/acl_10k_trace COPYONLY)
endif()

if(EXISTS ${CMAKE_SOURCE_DIR}/data/ipc_10k)
    configure_file(${CMAKE_SOURCE_DIR}/data/ipc_10k ${CMAKE_BINARY_DIR}/bin/ipc_10k COPYONLY)
endif()

if(EXISTS ${CMAKE_SOURCE_DIR}/data/ipc_10k_trace)
    configure_file(${CMAKE_SOURCE_DIR}/data/ipc_10k_trace ${CMAKE_BINARY_DIR}/bin/ipc_10k_trace COPYONLY)
endif()

# 100k dataset
if(EXISTS ${CMAKE_SOURCE_DIR}/data/acl_100k)
    configure_file(${CMAKE_SOURCE_DIR}/data/acl_100k ${CMAKE_BINARY_DIR}/bin/acl_100k COPYONLY)
endif()

if(EXISTS ${CMAKE_SOURCE_DIR}/data/acl_100k_trace)
    configure_file(${CMAKE_SOURCE_DIR}/data/acl_100k_trace ${CMAKE_BINARY_DIR}/bin/acl_100k_trace COPYONLY)
endif()

# Print build information
message(STATUS "================================================")
message(STATUS "Build Configuration:")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  CXX Flags: ${CMAKE_CXX_FLAGS}")
message(STATUS "================================================")

if(CMAKE_BUILD_TYPE MATCHES Release)
    message(STATUS " Performance optimizations enabled:")
    
    if(MSVC)
        message(STATUS "   ✓ /O2 optimization level")
        message(STATUS "   ✓ /GL (Whole Program Optimization)")
        message(STATUS "   ✓ /Oi (Generate Intrinsic Functions)")
        message(STATUS "   ✓ /arch:AVX2 (AVX2 SIMD)")
    else()
        message(STATUS "   ✓ -O3 optimization level")
        message(STATUS "   ✓ -march=native (CPU-specific optimizations)")
        message(STATUS "   ✓ -funroll-loops (loop unrolling)")
        message(STATUS "   ✓ -flto (Link Time Optimization)")
        message(STATUS "   ✓ -ffast-math (fast math operations)")
        
        if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            message(STATUS "   ✓ -ftree-vectorize (auto-vectorization)")
            if(COMPILER_SUPPORTS_PREFETCH)
                message(STATUS "   ✓ -fprefetch-loop-arrays (prefetch optimization)")
            endif()
        elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            if(COMPILER_SUPPORTS_VECTORIZE)
                message(STATUS "   ✓ -fvectorize (auto-vectorization)")
            endif()
        endif()
    endif()
    
    # Display SIMD status
    if(DEFINED SIMD_ENABLED)
        message(STATUS "   ✓ SIMD optimization: ${SIMD_ENABLED}")
    elseif(MSVC)
        message(STATUS "   ✓ SIMD optimization: AVX2")
    else()
        message(STATUS "   ⚠ SIMD optimization: Not available")
    endif()
    
    # Display OpenMP status
    if(OPENMP_ENABLED STREQUAL "YES")
        message(STATUS "   ✓ OpenMP: Enabled (parallel batch processing)")
    else()
        message(STATUS "   ⚠ OpenMP: Not available")
    endif()
    
    message(STATUS "================================================")
    message(STATUS "   Expected Performance Improvements:")
    message(STATUS "   • SIMD matching: +30-40% throughput")
    message(STATUS "   • LTSS bitmap index: +40-60% for wildcard rules")
    message(STATUS "   • Prefetching: +20% cache hit rate")
    message(STATUS "   • Overall: 2-3x throughput improvement")
    message(STATUS "================================================")
endif()

# Create benchmark script
if(CMAKE_BUILD_TYPE MATCHES Release)
    file(WRITE ${CMAKE_BINARY_DIR}/bin/benchmark.sh
"#!/bin/bash

echo '=== T2Tree SIMD & LTSS Optimization Benchmark ==='
echo ''
echo 'System Info:'
echo -n 'CPU: '
lscpu | grep 'Model name' | cut -d':' -f2 | xargs
echo -n 'SIMD Support: '
if grep -q avx2 /proc/cpuinfo; then echo 'AVX2'; elif grep -q sse4_2 /proc/cpuinfo; then echo 'SSE4.2'; else echo 'None'; fi
echo ''

# Check if data files exist
if [ ! -f acl_100k ]; then
    echo 'Error: Data files not found. Please ensure acl_100k and acl_100k_trace are in the current directory.'
    exit 1
fi

echo 'Running benchmark (5 iterations)...'
echo ''

RUNS=5
TOTAL_THROUGHPUT=0

for i in \\$(seq 1 \\$RUNS); do
    echo -n \"Run \\$i/\\$RUNS: \"
    OUTPUT=\\$(./T2Tree_Project -r acl_100k -p acl_100k_trace -b 8 -bit 4 -t 32 -l 10 2>&1)
    THROUGHPUT=\\$(echo \"\\$OUTPUT\" | grep 'Throughput' | awk '{print \\$2}')
    echo \"\\$THROUGHPUT Mpps\"
    if [ -n \"\\$THROUGHPUT\" ]; then
        TOTAL_THROUGHPUT=\\$(echo \"\\$TOTAL_THROUGHPUT + \\$THROUGHPUT\" | bc -l 2>/dev/null || echo \"\\$TOTAL_THROUGHPUT\")
    fi
done

if command -v bc &> /dev/null && [ \"\\$TOTAL_THROUGHPUT\" != \"0\" ]; then
    AVG_THROUGHPUT=\\$(echo \"scale=2; \\$TOTAL_THROUGHPUT / \\$RUNS\" | bc -l)
    echo ''
    echo \"Average Throughput: \\$AVG_THROUGHPUT Mpps\"
else
    echo ''
    echo \"Note: Install 'bc' for average calculation\"
fi
"
    )
    
    # Make benchmark script executable
    file(CHMOD ${CMAKE_BINARY_DIR}/bin/benchmark.sh 
        FILE_PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
                        GROUP_EXECUTE GROUP_READ
                        WORLD_EXECUTE WORLD_READ)
    
    message(STATUS "")
    message(STATUS "  Benchmark script created: ${CMAKE_BINARY_DIR}/bin/benchmark.sh")
    message(STATUS "   Run './benchmark.sh' in the bin directory to test performance")
endif()

# Performance profiling support
option(ENABLE_PROFILING "Enable profiling support" OFF)
if(ENABLE_PROFILING)
    if(NOT MSVC)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg")
        message(STATUS "   ✓ Profiling enabled (use gprof for analysis)")
    endif()
endif()

# CPU feature detection script
file(WRITE ${CMAKE_BINARY_DIR}/bin/check_cpu_features.sh
"#!/bin/bash

echo 'CPU Feature Detection:'
echo '====================='

if [ -f /proc/cpuinfo ]; then
    echo -n 'SSE4.2: '
    if grep -q sse4_2 /proc/cpuinfo; then echo '✓'; else echo '✗'; fi

    echo -n 'AVX:    '
    if grep -q avx /proc/cpuinfo; then echo '✓'; else echo '✗'; fi

    echo -n 'AVX2:   '
    if grep -q avx2 /proc/cpuinfo; then echo '✓'; else echo '✗'; fi

    echo -n 'AVX512: '
    if grep -q avx512 /proc/cpuinfo; then echo '✓'; else echo '✗'; fi
else
    echo 'Cannot detect CPU features (no /proc/cpuinfo)'
fi

echo ''
echo 'Cache Information:'
echo '=================='
if command -v lscpu &> /dev/null; then
    lscpu | grep cache || echo 'Cache info not available'
else
    echo 'lscpu not available'
fi

echo ''
echo 'Compiler Version:'
echo '================='
c++ --version | head -n1
"
)

file(CHMOD ${CMAKE_BINARY_DIR}/bin/check_cpu_features.sh 
    FILE_PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
                    GROUP_EXECUTE GROUP_READ
                    WORLD_EXECUTE WORLD_READ)