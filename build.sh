#!/bin/bash

echo "=== T2Tree Optimized Two-Phase Search Build Script ==="
echo "Building T2Tree with Optimized Two-Phase Search..."

# Clean previous build
if [ -d "build" ]; then
    echo "Cleaning old build directory..."
    rm -rf build
fi

mkdir build
cd build

echo "Running CMake configuration..."
# Run cmake configuration
cmake .. -DCMAKE_BUILD_TYPE=Release

if [ $? -ne 0 ]; then
    echo "❌ CMake configuration failed!"
    exit 1
fi

echo "Starting compilation..."
# Compile the project using all available cores
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo "❌ Compilation failed!"
    exit 1
fi

echo ""
echo "✅ Build successful!"
echo ""
echo "📁 Executable location: build/bin/T2Tree_Project"
echo ""
echo "🚀 Run example:"
echo "   cd build/bin"
echo "   ./T2Tree_Project -r acl_100k -p acl_100k_trace -b 8 -bit 4 -t 32 -l 10"
echo ""
