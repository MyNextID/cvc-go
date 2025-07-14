#!/bin/bash

# install.sh - Download CVC library artifacts for Go integration
# Usage: ./install.sh [version] [--help]
# Example: ./install.sh v0.1.5

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
REPO_OWNER="MyNextID"
REPO_NAME="cvc"
GITHUB_API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}"
GITHUB_DOWNLOAD_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download"
LIB_DIR="lib"
INCLUDE_DIR="include"

# Print functions
print_info() {
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

show_help() {
    cat << EOF
CVC Library Installer for Go

USAGE:
    $0 [VERSION] [OPTIONS]

ARGUMENTS:
    VERSION     CVC library version to download (e.g., v0.1.5)
                If not provided, downloads the latest release

OPTIONS:
    --help      Show this help message
    --force     Overwrite existing files without prompting

EXAMPLES:
    $0                  # Download latest version
    $0 v0.1.5          # Download specific version
    $0 v0.1.5 --force  # Download and overwrite existing files

DESCRIPTION:
    This script downloads pre-compiled CVC library static libraries and headers
    for ALL supported platforms. This creates a complete Go module that users
    can install with just 'go get' - no additional setup required.

    Downloaded files are placed in:
    - lib/[platform]/[arch]/     Static libraries (.a/.lib) for all platforms
    - include/                   Header files (.h)

SUPPORTED PLATFORMS:
    - macOS (darwin): arm64, x86_64
    - Linux: x86_64, aarch64
    - Windows: x86_64

DEVELOPER WORKFLOW:
    1. Run this script to populate your Go module with all platform libraries
    2. Commit the downloaded files to version control
    3. Users can then simply 'go get your-module' with zero setup
EOF
}

detect_platform() {
    case "$(uname -s)" in
        Darwin*)
            PLATFORM="darwin"
            case "$(uname -m)" in
                arm64) ARCH="arm64" ;;
                x86_64) ARCH="x86_64" ;;
                *)
                    print_error "Unsupported macOS architecture: $(uname -m)"
                    exit 1
                    ;;
            esac
            ARCHIVE_EXT="tar.gz"
            LIB_EXT="a"
            ;;
        Linux*)
            PLATFORM="linux"
            case "$(uname -m)" in
                x86_64) ARCH="x86_64" ;;
                aarch64|arm64) ARCH="aarch64" ;;
                *)
                    print_error "Unsupported Linux architecture: $(uname -m)"
                    exit 1
                    ;;
            esac
            ARCHIVE_EXT="tar.gz"
            LIB_EXT="a"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            PLATFORM="windows"
            ARCH="x86_64"
            ARCHIVE_EXT="zip"
            LIB_EXT="lib"
            ;;
        *)
            print_error "Unsupported platform: $(uname -s)"
            exit 1
            ;;
    esac
    print_info "Detected platform: ${PLATFORM}/${ARCH}"
}

get_latest_version() {
    print_info "Fetching latest release information..."
    local latest_release
    latest_release=$(curl -L -s -H 'Accept: application/json' "${GITHUB_API_URL}/releases/latest")
    if [ $? -ne 0 ]; then
        print_error "Failed to fetch release information from GitHub API"
        exit 1
    fi

    local version
    version=$(echo "$latest_release" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
    if [ -z "$version" ]; then
        print_error "Could not parse latest version from GitHub API response"
        exit 1
    fi

    echo "$version"
}

verify_version() {
    local version="$1"
    print_info "Verifying version ${version} exists..."

    local response
    response=$(curl -L -s -o /dev/null -w "%{http_code}" "${GITHUB_API_URL}/releases/tags/${version}")
    if [ "$response" != "200" ]; then
        print_error "Version ${version} not found. Please check the version number."
        print_info "You can view available versions at: https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
        exit 1
    fi
    print_success "Version ${version} found"
}

copy_headers_with_structure() {
    local temp_dir="$1"
    local is_first_run="$2"

    # Only copy headers on first run to avoid duplicates
    if [ "$is_first_run" != "true" ]; then
        return 0
    fi

    print_info "Copying header files with proper directory structure..."

    # Remove existing include directory if it exists
    if [ -d "$INCLUDE_DIR" ]; then
        rm -rf "$INCLUDE_DIR"
    fi
    mkdir -p "$INCLUDE_DIR"

    # Find all header files in the extracted archive
    find "$temp_dir" -name "*.h" | while read -r header_file; do
        local filename=$(basename "$header_file")
        local relative_path="${header_file#$temp_dir/}"

        # Handle l8w8jwt headers - put them in l8w8jwt subdirectory
        if [[ "$relative_path" == *"l8w8jwt"* ]] || [[ "$filename" == l8w8jwt* ]]; then
            mkdir -p "${INCLUDE_DIR}/l8w8jwt"
            cp "$header_file" "${INCLUDE_DIR}/l8w8jwt/"
            print_success "Installed header: l8w8jwt/$filename"
        # Handle include/include nested structure - flatten it
        elif [[ "$relative_path" == "include/include/"* ]]; then
            # Extract just the filename and put it directly in include/
            cp "$header_file" "${INCLUDE_DIR}/"
            print_success "Installed header: $filename"
        # Handle other nested include structures
        elif [[ "$relative_path" == "include/"* ]]; then
            # Copy to include root, preserving any subdirectory structure after include/
            local target_path="${relative_path#include/}"
            if [[ "$target_path" == *"/"* ]]; then
                # Has subdirectory structure
                local target_dir=$(dirname "$target_path")
                mkdir -p "${INCLUDE_DIR}/${target_dir}"
                cp "$header_file" "${INCLUDE_DIR}/${target_path}"
                print_success "Installed header: $target_path"
            else
                # Direct file
                cp "$header_file" "${INCLUDE_DIR}/"
                print_success "Installed header: $filename"
            fi
        # Handle direct header files (crypto.h, cvc.h, etc.)
        else
            cp "$header_file" "${INCLUDE_DIR}/"
            print_success "Installed header: $filename"
        fi
    done
}

download_and_extract() {
    local version="$1"
    local platform="$2"
    local arch="$3"
    local is_first_run="$4"

    local archive_ext lib_ext
    case "$platform" in
        "darwin"|"linux")
            archive_ext="tar.gz"
            lib_ext="a"
            ;;
        "windows")
            archive_ext="zip"
            lib_ext="lib"
            ;;
        *)
            print_error "Unknown platform: $platform"
            return 1
            ;;
    esac

    local archive_name="libcvc-${platform}-${arch}.${archive_ext}"
    local download_url="${GITHUB_DOWNLOAD_URL}/${version}/${archive_name}"
    local temp_dir
    temp_dir=$(mktemp -d)

    print_info "Downloading ${archive_name}..."
    if ! curl -L -o "${temp_dir}/${archive_name}" "${download_url}"; then
        print_error "Failed to download ${archive_name}"
        rm -rf "$temp_dir"
        return 1
    fi
    print_success "Downloaded ${archive_name}"

    # Create target directories
    local lib_target_dir="${LIB_DIR}/${platform}/${arch}"
    mkdir -p "$lib_target_dir"

    print_info "Extracting ${archive_name}..."
    cd "$temp_dir"
    case "$archive_ext" in
        "tar.gz")
            if ! tar -xzf "$archive_name"; then
                print_error "Failed to extract tar.gz archive"
                cd - > /dev/null
                rm -rf "$temp_dir"
                return 1
            fi
            ;;
        "zip")
            if ! unzip -q "$archive_name"; then
                print_error "Failed to extract zip archive"
                cd - > /dev/null
                rm -rf "$temp_dir"
                return 1
            fi
            ;;
    esac
    cd - > /dev/null

    # Copy static library
    local lib_file
    lib_file=$(find "$temp_dir" -name "*.${lib_ext}" | head -1)
    if [ -z "$lib_file" ]; then
        print_error "No static library (.${lib_ext}) found in archive"
        rm -rf "$temp_dir"
        return 1
    fi

    cp "$lib_file" "$lib_target_dir/"
    print_success "Installed library: ${lib_target_dir}/$(basename "$lib_file")"

    # Copy headers (only on first run)
    copy_headers_with_structure "$temp_dir" "$is_first_run"

    rm -rf "$temp_dir"
    return 0
}

get_platform_archs() {
    local platform="$1"
    case "$platform" in
        "darwin")
            echo "arm64"
            ;;
        "linux")
            echo "x86_64 aarch64"
            ;;
        "windows")
            echo "x86_64"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Download all platforms
download_all_platforms() {
    local version="$1"
    local failed_downloads=()
    local platforms="darwin linux windows"
    local is_first_run=true

    print_info "Downloading CVC library for all platforms..."
    echo

    for platform in $platforms; do
        local archs
        archs=$(get_platform_archs "$platform")
        for arch in $archs; do
            print_info "Processing ${platform}/${arch}..."
            if ! download_and_extract "$version" "$platform" "$arch" "$is_first_run"; then
                failed_downloads+=("${platform}/${arch}")
                print_warning "Failed to download ${platform}/${arch}"
            fi
            is_first_run=false  # Only first extraction should copy headers
            echo
        done
    done

    if [ ${#failed_downloads[@]} -eq 0 ]; then
        print_success "All platforms downloaded successfully!"
    else
        print_warning "Some downloads failed:"
        for failed in "${failed_downloads[@]}"; do
            echo "  - $failed"
        done
        echo
        print_info "You can retry failed downloads by running the script again"
    fi
}

# Parse command line arguments
VERSION=""
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_help
            exit 0
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --*)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
        *)
            if [ -z "$VERSION" ]; then
                VERSION="$1"
            else
                print_error "Too many arguments. Only one version can be specified."
                echo "Use --help for usage information"
                exit 1
            fi
            shift
            ;;
    esac
done

main() {
    print_info "CVC Library Installer for Go (All Platforms)"
    echo

    # Get version
    if [ -z "$VERSION" ]; then
        print_info "No version specified, fetching latest release..."
        VERSION=$(get_latest_version)
        print_success "Latest version: $VERSION"
    else
        print_info "Requested version: $VERSION"
        verify_version "$VERSION"
    fi

    # Check for existing files
    if [ -d "$LIB_DIR" ] && [ "$(ls -A "$LIB_DIR" 2>/dev/null)" ] && [ "$FORCE" != "true" ]; then
        print_warning "Library files already exist in ${LIB_DIR}/"
        read -p "Overwrite existing files? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Installation aborted by user"
            exit 0
        fi
        print_info "Removing existing library files..."
        rm -rf "${LIB_DIR:?}"/*
    fi

    # Download everything
    download_all_platforms "$VERSION"

    echo
    print_success "CVC library $VERSION installed for all platforms!"
    print_info "Repository structure:"
    echo "  lib/"
    local platforms="darwin linux windows"
    for platform in $platforms; do
        local archs
        archs=$(get_platform_archs "$platform")
        for arch in $archs; do
            if [ -d "${LIB_DIR}/${platform}/${arch}" ]; then
                echo "    ├── ${platform}/${arch}/"
                ls "${LIB_DIR}/${platform}/${arch}/" | sed 's/^/    │   ├── /'
            fi
        done
    done
    echo "  include/"
    if [ -d "$INCLUDE_DIR" ]; then
        ls "$INCLUDE_DIR/" | sed 's/^/    ├── /'
    fi

    echo
    print_info "Next steps:"
    echo "  1. Commit all files to Git: git add lib/ include/ && git commit -m 'Add CVC $VERSION libraries'"
    echo "  2. Users can now simply: go get your-module"
    echo "  3. No installation required for end users!"
}

main "$@"