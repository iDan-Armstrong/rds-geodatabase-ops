# Smallest working stack: one t4g.micro in an existing VPC.
# Costs money while it runs. `terraform destroy` when the drill is done
# (deletion_protection is off here for that reason only).

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
  region = var.region

  default_tags {
    tags = {
      Project = "rds-geodatabase-ops"
    }
  }
}

module "egdb" {
  source = "../../modules/egdb-postgres"

  name                       = "egdb-lab"
  engine_version             = var.engine_version
  vpc_id                     = var.vpc_id
  subnet_ids                 = var.private_subnet_ids
  allowed_security_group_ids = var.client_security_group_ids

  instance_class               = "db.t4g.micro"
  allocated_storage_gb         = 20
  max_allocated_storage_gb     = 20
  backup_retention_days        = 1
  deletion_protection          = false
  enhanced_monitoring_interval = 0

  tags = {
    Owner              = var.owner
    Environment        = "lab"
    DataClassification = "public-test-data"
  }
}

output "endpoint" {
  value = module.egdb.endpoint
}

output "instance_identifier" {
  value = module.egdb.instance_identifier
}

output "master_user_secret_arn" {
  value = module.egdb.master_user_secret_arn
}
