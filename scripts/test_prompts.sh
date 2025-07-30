#!/bin/bash

# test_prompts.sh
# Comprehensive test script for prompts in eBPF MCP Server

set -e  # Exit on any error

# Configuration
SERVER_URL="http://localhost:8080/mcp"
KPROBE_URL="https://github.com/cilium/ebpf/raw/refs/heads/main/examples/kprobe/bpf_bpfel.o"
TEST_FILE="/tmp/kprobe_test.o"
SESSION_ID=""
TOKEN=""
PROGRAM_ID=""
MAP_ID=""
LINK_ID=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if server is running
check_server() {
    log_info "Checking if eBPF MCP server is running..."
    
    if ! curl -s "$SERVER_URL" > /dev/null 2>&1; then
        log_error "Server is not running at $SERVER_URL"
        log_info "Please start the server with: sudo ./bin/ebpf-mcp-server -t http -debug"
        exit 1
    fi
    
    log_success "Server is running"
}

# Get authentication token from server logs or environment
get_auth_token() {
    log_info "Getting authentication token..."
    
    if [ -n "$MCP_AUTH_TOKEN" ]; then
        TOKEN="$MCP_AUTH_TOKEN"
        log_success "Using token from environment variable"
    elif [ -n "$1" ]; then
        TOKEN="$1"
        log_success "Using token from command line argument"
    else
        log_warning "No MCP_AUTH_TOKEN environment variable found"
        log_info "Please check server logs for the Bearer token or set MCP_AUTH_TOKEN"
        log_info "Or run with: $0 <token>"
        read -p "Enter the Bearer token from server logs: " TOKEN
    fi
    
    if [ -z "$TOKEN" ]; then
        log_error "No authentication token provided"
        exit 1
    fi
}


# Initialize MCP session
init_session() {
    log_info "Initializing MCP session..."
    
    local response=$(curl -s -X POST "$SERVER_URL" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d '{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"prompts": {}},
                "clientInfo": {"name": "ebpf-prompt-test-client", "version": "1.0.0"}
            }
        }')
     
    # Extract session ID from headers
    SESSION_ID=$(curl -s -X POST "$SERVER_URL" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -D - \
        -d '{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"prompts": {}},
                "clientInfo": {"name": "ebpf-prompt-test-client", "version": "1.0.0"}
            }
        }' 2>/dev/null | grep -i "mcp-session-id" | cut -d: -f2 | tr -d ' \r\n')
    
    if [ -z "$SESSION_ID" ]; then
        log_warning "No session ID found in headers, continuing without it"
        SESSION_ID="test-session"
    fi
    
    log_success "Session initialized: $SESSION_ID"
}

# Make MCP request
make_mcp_request() {
    local method="$1"
    local params="$2"
    local id="${3:-$(date +%s)}"
    
    local headers=(-H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN")
    if [ -n "$SESSION_ID" ]; then
        headers+=(-H "MCP-Session-ID: $SESSION_ID")
    fi
    
    local payload=$(cat << EOF
{
    "jsonrpc": "2.0",
    "id": $id,
    "method": "$method",
    "params": $params
}
EOF
)
    
    local response=$(curl -s -X POST "$SERVER_URL" "${headers[@]}" -d "$payload")
    
    echo "$response"
}

check_test_result() {
    local test_name="$1"
    local response="$2"
    local should_succeed="${3:-true}"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    
    log_info "Running test: $test_name"
    
    # Check if response contains error
    if echo "$response" | grep -q '"error"'; then
        if [ "$should_succeed" = "true" ]; then
            log_error "Test failed: $test_name"
            log_error "Response: $response"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            return 1
        else
            log_success "Test passed (expected failure): $test_name"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            return 0
        fi
    else
        if [ "$should_succeed" = "true" ]; then
            # Check if response contains success indicators
            if echo "$response" | grep -q '"result"' && echo "$response" | grep -q '"messages"'; then
                log_success "Test passed: $test_name"
                TESTS_PASSED=$((TESTS_PASSED + 1))
                return 0
            else
                log_error "Test failed: $test_name (no result/messages in response)"
                log_error "Response: $response"
                TESTS_FAILED=$((TESTS_FAILED + 1))
                return 1
            fi
        else
            log_error "Test failed: $test_name (expected error but got success)"
            log_error "Response: $response"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            return 1
        fi
    fi
}

# Test 1: Download eBPF program
test_download() {
    log_info "Test 1: Downloading eBPF kprobe program..."
    
    # Remove existing file
    rm -f "$TEST_FILE"
    
    # Download the kprobe example
    if curl -L -o "$TEST_FILE" "$KPROBE_URL"; then
        log_success "Downloaded eBPF program to $TEST_FILE"
        
        # Verify file
        local file_size=$(stat -f%z "$TEST_FILE" 2>/dev/null || stat -c%s "$TEST_FILE" 2>/dev/null)
        log_info "File size: $file_size bytes"
        
        # Check if it's a valid ELF file
        if file "$TEST_FILE" | grep -q "ELF"; then
            log_success "File is a valid ELF object"
        else
            log_warning "File may not be a valid ELF object"
        fi
    else
        log_error "Failed to download eBPF program"
        exit 1
    fi
}

# List available prompts
test_list_prompts() {
    log_info "Test: Listing available prompts..."

    local response=$(make_mcp_request "prompts/list" "{}")

    if echo "$response" | jq -e '.result.prompts' > /dev/null 2>&1; then
        local prompt_count=$(echo "$response" | jq '.result.prompts | length')
        
        if [[ "$prompt_count" -eq 0 ]]; then
            log_error "No prompts found"
            echo "$response" | jq '.'
            exit 1
        fi

        log_success "Found $prompt_count prompts"
        echo "$response" | jq -r '.result.prompts[].name' | while read prompt; do
            log_info "  - $prompt"
        done
    else
        log_error "Failed to list prompts"
        echo "$response" | jq '.'
        exit 1
    fi
}

test_get_empty_prompt() {
    log_info "Test: Get empty prompt name"

    local response=$(make_mcp_request "prompts/get" "{}")
    local error_msg=$(echo "$response" | jq -r '.error.message // empty')

    if [[ "$error_msg" == *"prompt not found"* ]]; then
        log_success "Received expected error: '$error_msg'"
    else
        log_error "Unexpected response or error: '$error_msg'"
        exit 1
    fi
}

test_get_prompt_missing_args() {
    log_info "Test: Get load_and_attach prompt without args"

    local params=$(cat << 'EOF'
{
    "name": "load_and_attach",
    "arguments": {
    }
}
EOF
)

    local response=$(make_mcp_request "prompts/get" "$params")
    local error_msg=$(echo "$response" | jq -r '.error.message // empty')

    if [[ "$error_msg" == *"missing required argument"* ]]; then
        log_success "Received expected error: '$error_msg'"
    else
        log_error "Unexpected response or error: '$error_msg'"
        exit 1
    fi
}

test_get_prompt_with_args() {
    log_info "Test: Get load_and_attach prompt with args"

    local arguments="{
        \"name\": \"load_and_attach\",
        \"arguments\": {
            \"source_type\": \"file\",
            \"source_value\": \"$TEST_FILE\",
            \"program_type\": \"XDP\",
            \"attach_type\": \"xdp\",
            \"target\": \"eth0\"
        }
    }"
    local response=$(make_mcp_request "prompts/get" "$arguments")
    local error_msg=$(echo "$response" | jq -r '.error.message // empty')

    if [[ "$error_msg" == *"missing required argument"* ]]; then
        log_success "Received expected error: '$error_msg'"
    else
        log_error "Unexpected response or error: '$error_msg'"
        exit 1
    fi
}

# Test 1: Basic XDP program load and attach
test_basic_xdp() {
    log_info "Test: Basic XDP program load and attach"
    local params=$(cat << 'EOF'
{
    "name": "load_and_attach",
    "arguments": {
        "source_type": "file",
        "source_value": "./test_data/test_program.o",
        "program_type": "XDP",
        "attach_type": "xdp",
        "target": "eth0"
    }
}
EOF
)
    
    local response=$(make_mcp_request "prompts/get" "$params")
    echo "$response" | jq '.'
}

# Test 2: KPROBE with base64 data
test_kprobe_base64() {
    local base64_data=$(cat "$TEST_DIR/test_program_b64.txt" 2>/dev/null || echo "VGVzdCBkYXRh")
    
    local params=$(cat << EOF
{
    "name": "load_and_attach",
    "arguments": {
        "source_type": "data",
        "source_value": "$base64_data",
        "program_type": "KPROBE",
        "attach_type": "kprobe",
        "target": "sys_open",
        "pin_path": "/sys/fs/bpf/test_kprobe"
    }
}
EOF
)
    
    local response=$(make_mcp_request "prompts/get" "$params")
    check_test_result "KPROBE with Base64 Data" "$response"
}

# Test 3: URL-based program with checksum
test_url_with_checksum() {
    local params=$(cat << 'EOF'
{
    "name": "load_and_attach",
    "arguments": {
        "source_type": "url",
        "source_value": "https://example.com/program.o",
        "program_type": "TRACEPOINT",
        "attach_type": "tracepoint",
        "target": "syscalls:sys_enter_open",
        "checksum": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "flags": "0",
        "priority": "10"
    }
}
EOF
)
    
    local response=$(make_mcp_request "prompts/get" "$params")
    check_test_result "URL with Checksum and Options" "$response"
}

# Test 4: Verify only mode
test_verify_only() {
    local params=$(cat << 'EOF'
{
    "name": "load_and_attach",
    "arguments": {
        "source_type": "file",
        "source_value": "./test_data/test_program.o",
        "program_type": "XDP",
        "attach_type": "xdp",
        "target": "eth0",
        "verify_only": "true"
    }
}
EOF
)
    
    local response=$(make_mcp_request "prompts/get" "$params")
    check_test_result "Verify Only Mode" "$response"
}

# Test 5: Invalid source type (should fail)
test_invalid_source_type() {
    local params=$(cat << 'EOF'
{
    "name": "load_and_attach",
    "arguments": {
        "source_type": "invalid",
        "source_value": "./test_data/test_program.o",
        "program_type": "XDP",
        "attach_type": "xdp",
        "target": "eth0"
    }
}
EOF
)
    
    local response=$(make_mcp_request "prompts/get" "$params")
    check_test_result "Invalid Source Type" "$response" "false"
}

# Test 6: Missing required arguments (should fail)
test_missing_arguments() {
    local params=$(cat << 'EOF'
{
    "name": "load_and_attach",
    "arguments": {
        "source_type": "file",
        "program_type": "XDP"
    }
}
EOF
)
    
    local response=$(make_mcp_request "prompts/get" "$params")
    check_test_result "Missing Required Arguments" "$response" "false"
}

# Test 7: CGROUP program
test_cgroup_program() {
    local params=$(cat << 'EOF'
{
    "name": "load_and_attach",
    "arguments": {
        "source_type": "file",
        "source_value": "./test_data/test_program.o",
        "program_type": "CGROUP_SKB",
        "attach_type": "cgroup",
        "target": "/sys/fs/cgroup/unified/test",
        "section": "cgroup_skb/ingress",
        "btf_path": "/sys/kernel/btf/vmlinux"
    }
}
EOF
)
    
    local response=$(make_mcp_request "prompts/get" "$params")
    check_test_result "CGROUP Program with BTF" "$response"
}

# Run all tests
run_all_tests() {
    log_info "Starting eBPF MCP prompt tests..."
    
    test_download
    test_list_prompts
    test_get_empty_prompt
    test_get_prompt_missing_args
    test_get_prompt_with_args
    
    # Print summary
    echo
    log_info "Test Summary:"
    log_info "Tests run: $TESTS_RUN"
    log_success "Tests passed: $TESTS_PASSED"
    if [ $TESTS_FAILED -gt 0 ]; then
        log_error "Tests failed: $TESTS_FAILED"
    else
        log_success "Tests failed: $TESTS_FAILED"
    fi
    
    if [ $TESTS_FAILED -gt 0 ]; then
        log_error "Some tests failed!"
        exit 1
    else
        log_success "All tests passed!"
    fi
}

# Main execution
main() {
    echo "=============================================="
    echo "    eBPF MCP Server Comprehensive Test"
    echo "=============================================="
    echo
    
    # Pre-flight checks
    check_server
    get_auth_token "$1"
    init_session
    
    echo
    echo "Running test suite..."
    echo

    run_all_tests
}

# Run main function with all arguments
main "$@"