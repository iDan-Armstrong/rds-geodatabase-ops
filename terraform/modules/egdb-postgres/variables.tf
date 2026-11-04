variable "name" {
  description = "Identifier for the instance and the prefix for every resource this module creates."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,40}$", var.name))
    error_message = "name must start with a letter and use lowercase letters, digits and hyphens (max 41 chars)."
  }
}

variable "vpc_id" {
  description = "VPC that holds the database. ArcGIS clients must run in the same cloud and region."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnets (at least two AZs) for the DB subnet group."
  type        = list(string)

  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "RDS needs subnets in at least two availability zones."
  }
}

variable "allowed_security_group_ids" {
  description = "Security groups (ArcGIS Server, Pro on EC2, admin bastion) allowed to reach port 5432. No CIDR ingress is ever created."
  type        = list(string)
  default     = []
}

variable "engine_version" {
  description = "RDS for PostgreSQL engine version. No default on purpose: pick a version on the Esri support matrix for your ArcGIS release and run `rdsops compat` before changing it."
  type        = string

  validation {
    condition     = can(regex("^(1[4-8])\\.[0-9]+$", var.engine_version))
    error_message = "engine_version must be MAJOR.MINOR for PostgreSQL 14 through 18 (for example 17.7)."
  }
}

variable "instance_class" {
  description = "Instance class. The examples use the smallest burstable class to keep cost down."
  type        = string
  default     = "db.t4g.micro"
}

variable "allocated_storage_gb" {
  description = "Initial gp3 storage in GB."
  type        = number
  default     = 20
}

variable "max_allocated_storage_gb" {
  description = "Storage autoscaling ceiling in GB. Set equal to allocated_storage_gb to turn autoscaling off."
  type        = number
  default     = 100
}

variable "database_name" {
  description = "Initial database. Esri's AWS deployment tools use egdb, so this module does too."
  type        = string
  default     = "egdb"
}

variable "master_username" {
  description = "RDS master user. Not the geodatabase admin: the sde login is created inside the database (see docs)."
  type        = string
  default     = "rdsadmin_gis"
}

variable "multi_az" {
  description = "Standby in a second AZ. Off by default because it doubles instance cost; turn on for production."
  type        = bool
  default     = false
}

variable "backup_retention_days" {
  description = "Automated backup retention, which also bounds point-in-time restore."
  type        = number
  default     = 7

  validation {
    condition     = var.backup_retention_days >= 1 && var.backup_retention_days <= 35
    error_message = "backup_retention_days must be 1 to 35. Zero would turn off backups and PITR."
  }
}

variable "deletion_protection" {
  description = "Block deletes at the API. Leave on outside throwaway test stacks."
  type        = bool
  default     = true
}

variable "auto_minor_version_upgrade" {
  description = "Off by default: minor upgrades go through the upgrade runbook so the Esri compatibility check runs first (ADR 0004)."
  type        = bool
  default     = false
}

variable "performance_insights_enabled" {
  description = "Performance Insights with 7-day retention."
  type        = bool
  default     = true
}

variable "enhanced_monitoring_interval" {
  description = "Enhanced Monitoring interval in seconds (0, 1, 5, 10, 15, 30, 60). 0 turns it off and skips the IAM role."
  type        = number
  default     = 60

  validation {
    condition     = contains([0, 1, 5, 10, 15, 30, 60], var.enhanced_monitoring_interval)
    error_message = "enhanced_monitoring_interval must be one of 0, 1, 5, 10, 15, 30, 60."
  }
}

variable "ca_cert_identifier" {
  description = "Server certificate authority for TLS."
  type        = string
  default     = "rds-ca-rsa2048-g1"
}

variable "logical_replication" {
  description = "Set rds.logical_replication = 1. Needed only for a blue/green major version upgrade (or DMS); it raises WAL volume, so leave it off otherwise. Changing it needs a reboot."
  type        = bool
  default     = false
}

variable "work_mem_kb" {
  description = "work_mem in KB. Spatial joins and sorts benefit from more than the engine default."
  type        = number
  default     = 16384
}

variable "log_min_duration_ms" {
  description = "Log statements slower than this many milliseconds. -1 turns it off."
  type        = number
  default     = 2000
}

variable "pgaudit_log" {
  description = "pgaudit.log classes. ddl and role cover schema and privilege changes without logging every read."
  type        = string
  default     = "ddl,role"
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic for CloudWatch alarm notifications. Null creates the alarms without actions."
  type        = string
  default     = null
}

variable "alarm_thresholds" {
  description = "CloudWatch alarm thresholds."
  type = object({
    cpu_percent          = optional(number, 80)
    free_storage_bytes   = optional(number, 5368709120) # 5 GiB
    freeable_memory_byte = optional(number, 134217728)  # 128 MiB
    connections          = optional(number, 80)
  })
  default = {}
}

variable "tags" {
  description = "Tags applied to every resource. Owner, Environment and DataClassification are required."
  type        = map(string)

  validation {
    condition = alltrue([
      for k in ["Owner", "Environment", "DataClassification"] : contains(keys(var.tags), k)
    ])
    error_message = "tags must include Owner, Environment and DataClassification."
  }
}
