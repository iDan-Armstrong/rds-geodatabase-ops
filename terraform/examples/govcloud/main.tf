# Production-shaped settings for an AWS GovCloud (US) account.
# The module builds every ARN from aws_partition, so the same code runs in the
# aws-us-gov partition without edits. Not exercised against a live GovCloud
# account in this repo; CI validates and scans it like the other examples.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60, < 7.0"
    }
  }
}

provider "aws" {
  region = var.region # us-gov-west-1 or us-gov-east-1

  # FIPS 140 validated endpoints for every API call Terraform makes.
  use_fips_endpoint = true

  default_tags {
    tags = {
      Project = "rds-geodatabase-ops"
    }
  }
}

module "egdb" {
  source = "../../modules/egdb-postgres"

  name                       = "egdb-prod"
  engine_version             = var.engine_version
  vpc_id                     = var.vpc_id
  subnet_ids                 = var.private_subnet_ids
  allowed_security_group_ids = var.client_security_group_ids

  instance_class           = "db.r6g.large"
  allocated_storage_gb     = 200
  max_allocated_storage_gb = 1000
  multi_az                 = true
  backup_retention_days    = 35
  deletion_protection      = true
  alarm_sns_topic_arn      = var.alarm_sns_topic_arn

  tags = {
    Owner              = var.owner
    Environment        = "production"
    DataClassification = "cui"
  }
}

output "endpoint" {
  value = module.egdb.endpoint
}

output "instance_identifier" {
  value = module.egdb.instance_identifier
}
