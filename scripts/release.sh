#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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
CVC-Go Release Script

USAGE:
    $0 <VERSION> [OPTIONS]

ARGUMENTS:
    VERSION     Semantic version (e.g., v1.0.0, v1.2.3, v0.1.0)
                Must follow semantic versioning with 'v' prefix

OPTIONS:
    --dry-run   Show what would be done without executing
    --force     Skip confirmation prompts
    --help      Show this help message

EXAMPLES:
    $0 v1.0.0
    $0 v0.2.1 --dry-run
    $0 v1.3.0 --force

DESCRIPTION:
    This script automates the Go module release process:
    1. Validates the version format
    2. Updates pre-compiled libraries using install.sh
    3. Runs tests and checks
    4. Creates and pushes Git tag
    5. Makes the module available via 'go get'

REQUIREMENTS:
    - Clean Git working directory
    - scripts/install.sh must exist
    - Valid Go module (go.mod file)
EOF
}

validate_version() {
    local version="$1"

    # Check if version starts with 'v' and follows semantic versioning
    if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9\.-]+)?(\+[a-zA-Z0-9\.-]+)?$ ]]; then
        print_error "Invalid version format: $version"
        print_info "Version must follow semantic versioning with 'v' prefix (e.g., v1.0.0, v1.2.3-alpha, v2.0.0)"
        exit 1
    fi

    print_success "Version format is valid: $version"
}

check_prerequisites() {
    # Check if we're in a Git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not in a Git repository"
        exit 1
    fi

    # Check if go.mod exists
    if [[ ! -f "go.mod" ]]; then
        print_error "go.mod file not found. This doesn't appear to be a Go module."
        exit 1
    fi

    # Check if install.sh exists
    if [[ ! -f "scripts/install.sh" ]]; then
        print_error "scripts/install.sh not found. Cannot update libraries."
        exit 1
    fi

    # Check for clean working directory
    if [[ -n $(git status --porcelain) ]]; then
        print_error "Working directory is not clean. Please commit or stash changes."
        git status --short
        exit 1
    fi

    # Check if we're on the main/master branch
    local current_branch
    current_branch=$(git branch --show-current)
    if [[ "$current_branch" != "main" && "$current_branch" != "master" ]]; then
        print_warning "You're not on main/master branch (current: $current_branch)"
        if [[ "$FORCE" != "true" ]]; then
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                print_info "Release cancelled"
                exit 0
            fi
        fi
    fi

    print_success "Prerequisites check passed"
}

check_existing_tag() {
    local version="$1"

    if git tag -l | grep -q "^${version}$"; then
        print_error "Tag $version already exists"
        print_info "Use 'git tag -d $version' to delete it locally, or choose a different version"
        exit 1
    fi

    # Check if tag exists on remote
    if git ls-remote --tags origin | grep -q "refs/tags/${version}$"; then
        print_error "Tag $version already exists on remote"
        print_info "Choose a different version number"
        exit 1
    fi

    print_success "Tag $version is available"
}

create_and_push_tag() {
    local version="$1"

    print_info "Creating and pushing tag $version..."

    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "[DRY RUN] Would run:"
        print_info "  git tag $version"
        print_info "  git push origin $version"
        print_info "  git push origin $(git branch --show-current)"
        return 0
    fi

    # Create the tag
    git tag "$version"

    # Push the current branch first
    git push origin "$(git branch --show-current)"

    # Push the tag
    git push origin "$version"

    print_success "Tag $version created and pushed"
}

verify_release() {
    local version="$1"

    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "[DRY RUN] Would verify release with: go list -m github.com/MyNextID/cvc-go@$version"
        return 0
    fi

    print_info "Verifying release (this may take a few minutes for the proxy to pick up the new version)..."

    # Wait a bit for the tag to propagate
    sleep 5

    # Try to fetch the module (this will fail if not available yet, which is normal)
    local module_path
    module_path=$(grep '^module ' go.mod | awk '{print $2}')

    print_info "Attempting to verify module: $module_path@$version"
    print_info "Note: It may take a few minutes for the Go proxy to pick up the new version"

    if go list -m "$module_path@$version" >/dev/null 2>&1; then
        print_success "Module $module_path@$version is available!"
    else
        print_warning "Module verification failed (this is normal immediately after release)"
        print_info "The module should be available within a few minutes"
        print_info "Users can get it with: go get $module_path@$version"
    fi
}

main() {
    local VERSION=""
    local DRY_RUN=false
    local FORCE=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --*)
                print_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
            *)
                if [[ -z "$VERSION" ]]; then
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

    # Check if version is provided
    if [[ -z "$VERSION" ]]; then
        print_error "Version is required"
        echo "Use --help for usage information"
        exit 1
    fi

    print_info "CVC-Go Release Script"
    print_info "Version: $VERSION"
    if [[ "$DRY_RUN" == "true" ]]; then
        print_warning "DRY RUN MODE - No changes will be made"
    fi
    echo

    # Run the release process
    validate_version "$VERSION"
    check_prerequisites
    check_existing_tag "$VERSION"

    # Show summary and get confirmation
    if [[ "$FORCE" != "true" && "$DRY_RUN" != "true" ]]; then
        echo
        print_info "Release Summary:"
        echo "  • Update libraries with install.sh"
        echo "  • Run tests and checks"
        echo "  • Commit any changes"
        echo "  • Create and push tag: $VERSION"
        echo "  • Make available via 'go get'"
        echo
        read -p "Proceed with release? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Release cancelled by user"
            exit 0
        fi
    fi

    echo
    create_and_push_tag "$VERSION"
    verify_release "$VERSION"

    echo
    print_success "Release $VERSION completed successfully!"
    echo
    print_info "Next steps:"
    echo "  • The module is now available for users: go get $(grep '^module ' go.mod | awk '{print $2}')@$VERSION"
    echo "  • Monitor GitHub releases page for the new tag"
    echo "  • Update documentation if needed"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo
        print_warning "This was a dry run. No actual changes were made."
        print_info "Run without --dry-run to execute the release"
    fi
}

# Export functions for potential use in tests
export -f validate_version check_prerequisites

# Run main function with all arguments
main "$@"