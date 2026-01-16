#!/bin/bash

# ESP32 NAT Router - Multi-Target Build Script
# Compiles for ESP32, ESP32-C2, and ESP32-S3 sequentially

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to build for specific target
build_target() {
    local target=$1
    local description=$2
    
    print_status "Building for $description ($target)..."
    
    # Set target using idf.py
    idf.py set-target $target
    
    # Clean previous build artifacts
    print_status "Cleaning previous build artifacts..."
    idf.py clean
    
    # Build project
    print_status "Starting compilation for $target..."
    if idf.py build; then
        # Save binary artifacts to separate directory
        save_binary_artifacts "$target" "$description"
        print_success "Build completed successfully for $target"
        return 0
    else
        print_error "Build failed for $target"
        return 1
    fi
}

# Function to save binary artifacts to separate directory
save_binary_artifacts() {
    local target=$1
    local description=$2
    local artifacts_dir="firmware_$target"
    
    print_status "Saving binary artifacts to $artifacts_dir/..."
    
    # Create artifacts directory if it doesn't exist
    mkdir -p "$artifacts_dir"
    
    # Find and copy relevant binary files
    local build_dir="build"
    local files_copied=0
    
    # Main firmware binary
    if [ -f "$build_dir/esp32_nat_router.bin" ]; then
        cp "$build_dir/esp32_nat_router.bin" "$artifacts_dir/"
        print_status "  ✓ Copied esp32_nat_router.bin"
        ((files_copied++))
    fi
    
    # Bootloader binary
    if [ -f "$build_dir/bootloader/bootloader.bin" ]; then
        cp "$build_dir/bootloader/bootloader.bin" "$artifacts_dir/"
        print_status "  ✓ Copied bootloader.bin"
        ((files_copied++))
    fi
    
    # Partition table
    if [ -f "$build_dir/partition_table/partition-table.bin" ]; then
        cp "$build_dir/partition_table/partition-table.bin" "$artifacts_dir/"
        print_status "  ✓ Copied partition-table.bin"
        ((files_copied++))
    fi
    
    # Combined firmware (if available)
    if [ -f "$build_dir/esp32_nat_router-merged.bin" ]; then
        cp "$build_dir/esp32_nat_router-merged.bin" "$artifacts_dir/"
        print_status "  ✓ Copied esp32_nat_router-merged.bin"
        ((files_copied++))
    fi
    
    # Copy any other .bin files
    for bin_file in "$build_dir"/*.bin; do
        if [ -f "$bin_file" ]; then
            local filename=$(basename "$bin_file")
            if [ ! -f "$artifacts_dir/$filename" ]; then
                cp "$bin_file" "$artifacts_dir/"
                print_status "  ✓ Copied $filename"
                ((files_copied++))
            fi
        fi
    done
    
    # Create a version info file
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local git_hash=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    cat > "$artifacts_dir/build_info.txt" << EOF
ESP32 NAT Router Build Information
=================================
Target: $description ($target)
Build Time: $timestamp
Git Hash: $git_hash
Binary Files: $files_copied
Build Directory: $build_dir
EOF
    
    print_status "  ✓ Created build_info.txt"
    print_success "Saved $files_copied binary files to $artifacts_dir/"
}

# Function to check if idf.py is available
check_idf_env() {
    if ! command -v idf.py &> /dev/null; then
        print_error "idf.py not found. ESP-IDF environment not set up properly."
        print_error "Please source ESP-IDF export script first:"
        print_error "  source /path/to/esp-idf/export.sh"
        exit 1
    fi
}

# Main script execution
main() {
    print_status "ESP32 NAT Router Multi-Target Build Script"
    print_status "========================================"
    
    # Check if ESP-IDF environment is set up
    check_idf_env
    
    # Store current directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"
    
    print_status "Working directory: $(pwd)"
    
    # Define targets and their descriptions
    declare -A TARGETS=(
        ["esp32"]="ESP32 (Original)"
        ["esp32c2"]="ESP32-C2" 
        ["esp32s3"]="ESP32-S3"
    )
    
    # Array to store failed targets
    FAILED_TARGETS=()
    
    # Build for each target
    for target in "esp32" "esp32c2" "esp32s3"; do
        description="${TARGETS[$target]}"
        echo ""
        print_status "=========================================="
        
        if ! build_target "$target" "$description"; then
            FAILED_TARGETS+=("$target")
        fi
        
        echo ""
    done
    
    # Final summary
    print_status "=========================================="
    print_status "Build Summary"
    print_status "=========================================="
    
    if [ ${#FAILED_TARGETS[@]} -eq 0 ]; then
        print_success "All targets built successfully!"
        print_status "Binary artifacts are preserved in firmware directories:"
        for target in "esp32" "esp32c2" "esp32s3"; do
            artifacts_dir="firmware_$target"
            if [ -d "$artifacts_dir" ]; then
                print_status "  - $artifacts_dir/ (preserved)"
            fi
        done
        print_status "Build directories (will be cleaned on next build):"
        for target in "esp32" "esp32c2" "esp32s3"; do
            if [ -d "build/$target" ]; then
                print_status "  - build/$target/"
            fi
        done
    else
        print_error "Build failed for ${#FAILED_TARGETS[@]} target(s):"
        for failed_target in "${FAILED_TARGETS[@]}"; do
            print_error "  - $failed_target (${TARGETS[$failed_target]})"
        done
        exit 1
    fi
    
    # Show preserved binary sizes
    echo ""
    print_status "Preserved Binary Sizes:"
    print_status "======================="
    for target in "esp32" "esp32c2" "esp32s3"; do
        artifacts_dir="firmware_$target"
        if [ -f "$artifacts_dir/esp32_nat_router.bin" ]; then
            size=$(stat -f%z "$artifacts_dir/esp32_nat_router.bin" 2>/dev/null || stat -c%s "$artifacts_dir/esp32_nat_router.bin" 2>/dev/null || echo "unknown")
            print_status "  $target: $size bytes ($artifacts_dir/esp32_nat_router.bin)"
        fi
    done
    
    # Show total size of all preserved artifacts
    echo ""
    total_size=0
    for target in "esp32" "esp32c2" "esp32s3"; do
        artifacts_dir="firmware_$target"
        if [ -d "$artifacts_dir" ]; then
            for bin_file in "$artifacts_dir"/*.bin; do
                if [ -f "$bin_file" ]; then
                    size=$(stat -f%z "$bin_file" 2>/dev/null || stat -c%s "$bin_file" 2>/dev/null || echo "0")
                    total_size=$((total_size + size))
                fi
            done
        fi
    done
    
    if [ $total_size -gt 0 ]; then
        if command -v numfmt &> /dev/null; then
            human_size=$(numfmt --to=iec $total_size)
        else
            human_size="${total_size} bytes"
        fi
        print_status "Total preserved artifacts: $human_size"
    fi
    
    print_success "Multi-target build script completed!"
    print_status "Binary artifacts are preserved in firmware_* directories and will not be cleaned."
}

# Handle script interruption
trap 'print_warning "Script interrupted by user"; exit 1' INT

# Run main function
main "$@"