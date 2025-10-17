#!/bin/bash

# Test script to demonstrate custom infrastructure functionality
# This script shows how to use the --terraform-dir flag with Stratus Red Team

echo "=== Custom Infrastructure Test for Stratus Red Team ==="
echo ""

# Check if we're in the right directory
if [ ! -f "main.tf" ]; then
    echo "Error: main.tf not found. Please run this script from the custom-infrastructure directory."
    exit 1
fi

echo "1. Testing help output to see the new --terraform-dir flag:"
echo "   stratus warmup --help | grep terraform-dir"
echo ""

echo "2. Example usage with custom infrastructure:"
echo "   # Warm up using custom infrastructure"
echo "   stratus warmup aws.persistence.iam-backdoor-user --terraform-dir ./examples/custom-infrastructure"
echo ""

echo "3. Example with detonation and cleanup:"
echo "   stratus detonate aws.persistence.iam-backdoor-user --terraform-dir ./examples/custom-infrastructure --cleanup"
echo ""

echo "4. Example with force cleanup:"
echo "   stratus cleanup aws.persistence.iam-backdoor-user --terraform-dir ./examples/custom-infrastructure --force"
echo ""

echo "=== Key Features ==="
echo "✓ Use your own Terraform infrastructure instead of embedded code"
echo "✓ Customize infrastructure for your specific environment"
echo "✓ Test attack techniques against your own infrastructure"
echo "✓ Maintain control over infrastructure lifecycle"
echo ""

echo "=== Important Notes ==="
echo "• Your Terraform outputs must match what the attack technique expects"
echo "• The custom Terraform directory won't be automatically cleaned up"
echo "• Use the --force flag when needed to override state checks"
echo "• Check attack technique documentation for required outputs"
echo "• Both relative and absolute paths are supported for --terraform-dir"
echo "• Relative paths are automatically converted to absolute paths"
echo ""

echo "=== Path Resolution Test ==="
echo "Testing relative path resolution:"
echo "Current directory: $(pwd)"
echo "Terraform file exists: $(ls -la main.tf 2>/dev/null && echo 'YES' || echo 'NO')"
echo "Absolute path: $(realpath . 2>/dev/null || pwd)"
