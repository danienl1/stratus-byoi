# Custom Infrastructure for Stratus Red Team

This example demonstrates how to use your own Terraform infrastructure with Stratus Red Team attack techniques instead of the embedded Terraform code.

## Overview

Forked version allows you to specify custom Terraform directories containing your own infrastructure prerequisites. This is useful when:

- You want to use your own existing infrastructure
- You want to test attack techniques against your own infrastructure setup
- You need to comply with specific organizational requirements

## Usage

### Basic Usage

Use the `--terraform-dir` flag with any Stratus Red Team command:

```bash

# Build 
cd v2
go build -o stratus ./cmd/stratus

# Warm up using custom infrastructure
stratus warmup aws.persistence.iam-backdoor-user --terraform-dir ./examples/custom-infrastructure
./stratus warmup aws.persistence.iam-backdoor-user --terraform-dir $TF_DIR

# Detonate using custom infrastructure
stratus detonate aws.persistence.iam-backdoor-user --terraform-dir ./examples/custom-infrastructure
./stratus detonate aws.persistence.iam-backdoor-user --terraform-dir $TF_DIR

# Clean up custom infrastructure
stratus cleanup aws.persistence.iam-backdoor-user --terraform-dir ./examples/custom-infrastructure
./stratus cleanup aws.persistence.iam-backdoor-user --terraform-dir $TF_DIR

```

### Example with Custom Infrastructure

This example creates a custom IAM user that can be used with attack techniques that require an IAM user as a prerequisite.

1. **Create your custom Terraform files** in a directory (e.g., `./my-custom-infra/`)
2. **Ensure your Terraform outputs match** what the attack technique expects
3. **Run Stratus Red Team** with the `--terraform-dir` flag pointing to your directory

### Terraform Output Requirements

Your custom Terraform must provide outputs that match what the attack technique expects. For example:

- `iam_user_name` - for techniques that need an IAM user
- `instance_id` - for techniques that need an EC2 instance
- `bucket_name` - for techniques that need an S3 bucket

Check the attack technique documentation to see what outputs are required.

### Notes
- The custom Terraform directory must contain valid Terraform files
- Your Terraform outputs must match the expected format for the attack technique
- The `display` output (if present) will be shown after warmup
- Both relative and absolute paths are supported for the `--terraform-dir` flag (may be buggy, wip)

### Example Commands

```bash
# Using relative paths (automatically converted to absolute paths)
stratus warmup aws.persistence.iam-backdoor-user --terraform-dir ./examples/custom-infrastructure
stratus detonate aws.persistence.iam-backdoor-user --terraform-dir ./examples/custom-infrastructure --cleanup
stratus cleanup aws.persistence.iam-backdoor-user --terraform-dir ./examples/custom-infrastructure --force

# Using absolute paths
stratus warmup aws.persistence.iam-backdoor-user --terraform-dir /path/to/your/custom-infrastructure
stratus detonate aws.persistence.iam-backdoor-user --terraform-dir /path/to/your/custom-infrastructure --cleanup
stratus cleanup aws.persistence.iam-backdoor-user --terraform-dir /path/to/your/custom-infrastructure --force
```

## File Structure

```
examples/custom-infrastructure/
├── main.tf          # Your custom Terraform configuration
└── README.md        # This documentation
```

## Customization

You can customize the Terraform configuration to:

- Use different AWS regions
- Add additional resources
- Modify resource configurations
- Add custom tags
- Use different naming conventions

Just ensure that the required outputs are still provided for the attack technique to work correctly.
