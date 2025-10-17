terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.71.0"
    }
  }
}

provider "aws" {
  skip_region_validation      = true
  skip_credentials_validation = true
  default_tags {
    tags = {
      StratusRedTeam = true
      CustomInfra    = true
    }
  }
}

# Example: Create a custom IAM user for testing
resource "random_string" "random" {
  length    = 8
  min_lower = 8
}

# Data resource to reference an existing IAM user
# Make sure this user exists in your AWS account before using
data "aws_iam_user" "custom_user" {
  user_name = "dletestuser"
}

# Any output named "display" is automatically printed by Stratus Red Team after the warm-up phase
output "display" {
  value = format("Custom IAM user %s is ready for testing", data.aws_iam_user.custom_user.user_name)
}

output "user_name" {
  value = data.aws_iam_user.custom_user.user_name
}

# Additional outputs that can be used by attack techniques
output "user_arn" {
  value = data.aws_iam_user.custom_user.arn
}
