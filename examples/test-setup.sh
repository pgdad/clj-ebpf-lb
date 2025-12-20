#!/bin/bash
#
# Test Environment Setup Script
#
# Creates an isolated network namespace with veth pairs for testing
# the reverse proxy without affecting the host network.
#
# Usage:
#   ./examples/test-setup.sh setup     # Create test environment
#   ./examples/test-setup.sh teardown  # Remove test environment
#   ./examples/test-setup.sh status    # Show current state
#
# After setup:
#   - Proxy interface: veth-proxy (10.99.1.1)
#   - Backend interface: veth-backend in test-ns namespace (10.99.1.2)
#   - Start backend: sudo ip netns exec test-ns python3 -m http.server 8080
#   - Attach proxy to veth-proxy interface

set -e

NAMESPACE="test-ns"
VETH_HOST="veth-proxy"
VETH_NS="veth-backend"
HOST_IP="10.99.1.1"
NS_IP="10.99.1.2"
SUBNET="10.99.1.0/24"

setup() {
    echo "Creating test network environment..."

    # Check if already exists
    if ip netns list | grep -q "^${NAMESPACE}"; then
        echo "Error: Namespace $NAMESPACE already exists. Run teardown first."
        exit 1
    fi

    # Create network namespace
    echo "Creating namespace: $NAMESPACE"
    sudo ip netns add "$NAMESPACE"

    # Create veth pair
    echo "Creating veth pair: $VETH_HOST <-> $VETH_NS"
    sudo ip link add "$VETH_HOST" type veth peer name "$VETH_NS"

    # Move one end to namespace
    sudo ip link set "$VETH_NS" netns "$NAMESPACE"

    # Configure host side
    echo "Configuring host interface: $VETH_HOST ($HOST_IP)"
    sudo ip addr add "${HOST_IP}/24" dev "$VETH_HOST"
    sudo ip link set "$VETH_HOST" up

    # Configure namespace side
    echo "Configuring namespace interface: $VETH_NS ($NS_IP)"
    sudo ip netns exec "$NAMESPACE" ip addr add "${NS_IP}/24" dev "$VETH_NS"
    sudo ip netns exec "$NAMESPACE" ip link set "$VETH_NS" up
    sudo ip netns exec "$NAMESPACE" ip link set lo up

    echo ""
    echo "=========================================="
    echo "Test environment created successfully!"
    echo "=========================================="
    echo ""
    echo "Network topology:"
    echo "  Host:      $VETH_HOST ($HOST_IP)"
    echo "  Namespace: $NAMESPACE / $VETH_NS ($NS_IP)"
    echo ""
    echo "Quick start:"
    echo ""
    echo "1. Start a backend server in the namespace:"
    echo "   sudo ip netns exec $NAMESPACE python3 -m http.server 8080"
    echo ""
    echo "2. Start the proxy attached to $VETH_HOST:"
    echo "   sudo clojure -M:run -i $VETH_HOST -p 80 -t ${NS_IP}:8080"
    echo ""
    echo "3. Test the proxy:"
    echo "   curl http://${HOST_IP}:80"
    echo ""
    echo "4. Cleanup when done:"
    echo "   ./examples/test-setup.sh teardown"
    echo ""
}

teardown() {
    echo "Removing test network environment..."

    # Delete veth (also removes the peer)
    if ip link show "$VETH_HOST" &>/dev/null; then
        echo "Removing veth pair..."
        sudo ip link del "$VETH_HOST"
    fi

    # Delete namespace
    if ip netns list | grep -q "^${NAMESPACE}"; then
        echo "Removing namespace: $NAMESPACE"
        sudo ip netns del "$NAMESPACE"
    fi

    echo "Cleanup complete."
}

status() {
    echo "Test Environment Status"
    echo "======================="
    echo ""

    # Check namespace
    if ip netns list | grep -q "^${NAMESPACE}"; then
        echo "Namespace: $NAMESPACE (exists)"
        echo ""
        echo "Namespace interfaces:"
        sudo ip netns exec "$NAMESPACE" ip -br addr show
    else
        echo "Namespace: $NAMESPACE (not found)"
    fi
    echo ""

    # Check host interface
    if ip link show "$VETH_HOST" &>/dev/null; then
        echo "Host interface: $VETH_HOST (exists)"
        ip -br addr show "$VETH_HOST"
    else
        echo "Host interface: $VETH_HOST (not found)"
    fi
    echo ""

    # Check for running backend
    if ip netns list | grep -q "^${NAMESPACE}"; then
        echo "Processes in namespace:"
        sudo ip netns exec "$NAMESPACE" ps aux 2>/dev/null | grep -v "^USER" || echo "(none)"
    fi
}

case "${1:-}" in
    setup)
        setup
        ;;
    teardown)
        teardown
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {setup|teardown|status}"
        echo ""
        echo "Commands:"
        echo "  setup     - Create isolated test network environment"
        echo "  teardown  - Remove test network environment"
        echo "  status    - Show current environment status"
        exit 1
        ;;
esac
