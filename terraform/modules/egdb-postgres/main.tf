# RDS for PostgreSQL instance prepared to host an ArcGIS enterprise geodatabase.
#
# What this module decides for you:
#   - encrypted at rest with a customer-managed KMS key (rotation on)
#   - TLS required (rds.force_ssl), IAM database auth available
#   - master password generated and held by RDS in Secrets Manager; never in state or tfvars
#   - pg_stat_statements and pgaudit preloaded so the rdsops checks have data to read
#   - no public endpoint and no CIDR ingress; only listed security groups reach 5432
#   - CloudWatch alarms for the four things that take a geodatabase down
#
# What it leaves to you: the VPC, the sde login and the geodatabase itself
# (created from ArcGIS Pro, see docs/geodatabase-on-rds.md).

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

locals {
  engine_major = split(".", var.engine_version)[0]
}

# ---------------------------------------------------------------- encryption

data "aws_iam_policy_document" "kms" {
  # checkov:skip=CKV_AWS_111: In a key policy, Resource "*" means this key only; principal is the owning account root.
  # checkov:skip=CKV_AWS_356: Same as above: key policies cannot name the key ARN they are attached to.
  # checkov:skip=CKV_AWS_109: Account root must administer its own key, or the key becomes unmanageable.
  # Account root administers the key; IAM policies then grant use. This is the
  # AWS default policy written out so it is reviewable (and so it is partition
  # aware for GovCloud).
  statement {
    sid       = "AccountAdministers"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "db" {
  description             = "${var.name}: RDS storage, snapshots, Performance Insights, master secret"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = var.tags
}

resource "aws_kms_alias" "db" {
  name          = "alias/${var.name}-db"
  target_key_id = aws_kms_key.db.key_id
}

# ------------------------------------------------------------------- network

resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = var.subnet_ids
  tags       = var.tags
}

resource "aws_security_group" "db" {
  name_prefix = "${var.name}-db-"
  description = "PostgreSQL 5432 for ${var.name}; ingress only from listed security groups"
  vpc_id      = var.vpc_id
  tags        = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "from_clients" {
  for_each = toset(var.allowed_security_group_ids)

  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = each.value
  description                  = "PostgreSQL from ${each.value}"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

# --------------------------------------------------------------- parameters

resource "aws_db_parameter_group" "this" {
  name_prefix = "${var.name}-pg${local.engine_major}-"
  family      = "postgres${local.engine_major}"
  description = "${var.name}: TLS required, auditing and query stats for geodatabase operations"
  tags        = var.tags

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name         = "shared_preload_libraries"
    value        = "pg_stat_statements,pgaudit"
    apply_method = "pending-reboot"
  }
  parameter {
    name  = "pgaudit.log"
    value = var.pgaudit_log
  }
  parameter {
    name  = "pg_stat_statements.track"
    value = "top"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = tostring(var.log_min_duration_ms)
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
  parameter {
    name  = "log_disconnections"
    value = "1"
  }
  parameter {
    name  = "log_lock_waits"
    value = "1"
  }
  parameter {
    name  = "work_mem"
    value = tostring(var.work_mem_kb)
  }
  parameter {
    name         = "rds.logical_replication"
    value        = var.logical_replication ? "1" : "0"
    apply_method = "pending-reboot"
  }
  parameter {
    name  = "random_page_cost"
    value = "1.1" # gp3 SSD; the 4.0 default steers the planner away from spatial indexes
  }

  lifecycle {
    create_before_destroy = true
  }
}

# --------------------------------------------------------------- monitoring

data "aws_iam_policy_document" "monitoring_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "monitoring" {
  count              = var.enhanced_monitoring_interval > 0 ? 1 : 0
  name_prefix        = "${var.name}-rds-mon-"
  assume_role_policy = data.aws_iam_policy_document.monitoring_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "monitoring" {
  count      = var.enhanced_monitoring_interval > 0 ? 1 : 0
  role       = aws_iam_role.monitoring[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# ----------------------------------------------------------------- instance

resource "aws_db_instance" "this" {
  # checkov:skip=CKV_AWS_226: Minor upgrades are deliberate, gated by the Esri compatibility check (ADR 0004).
  identifier     = var.name
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  db_name                       = var.database_name
  username                      = var.master_username
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.db.key_id

  storage_type          = "gp3"
  allocated_storage     = var.allocated_storage_gb
  max_allocated_storage = var.max_allocated_storage_gb
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.db.arn

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false
  multi_az               = var.multi_az
  ca_cert_identifier     = var.ca_cert_identifier
  parameter_group_name   = aws_db_parameter_group.this.name

  iam_database_authentication_enabled = true

  backup_retention_period   = var.backup_retention_days
  backup_window             = "07:00-08:00" # UTC; 02:00-03:00 US Eastern standard time
  maintenance_window        = "sun:08:30-sun:09:30"
  copy_tags_to_snapshot     = true
  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-final"

  auto_minor_version_upgrade  = var.auto_minor_version_upgrade
  allow_major_version_upgrade = false
  apply_immediately           = false

  performance_insights_enabled          = var.performance_insights_enabled
  performance_insights_kms_key_id       = var.performance_insights_enabled ? aws_kms_key.db.arn : null
  performance_insights_retention_period = var.performance_insights_enabled ? 7 : null

  monitoring_interval = var.enhanced_monitoring_interval
  monitoring_role_arn = var.enhanced_monitoring_interval > 0 ? aws_iam_role.monitoring[0].arn : null

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = var.tags

  depends_on = [aws_iam_role_policy_attachment.monitoring]
}

# ------------------------------------------------------------------- alarms

locals {
  alarm_actions = var.alarm_sns_topic_arn == null ? [] : [var.alarm_sns_topic_arn]
  thresholds    = var.alarm_thresholds

  alarms = {
    cpu = {
      metric      = "CPUUtilization"
      comparison  = "GreaterThanThreshold"
      threshold   = local.thresholds.cpu_percent
      description = "CPU above ${local.thresholds.cpu_percent}% for 15 minutes"
    }
    storage = {
      metric      = "FreeStorageSpace"
      comparison  = "LessThanThreshold"
      threshold   = local.thresholds.free_storage_bytes
      description = "Free storage low. A full volume stops writes, including sde state and lineage tables."
    }
    memory = {
      metric      = "FreeableMemory"
      comparison  = "LessThanThreshold"
      threshold   = local.thresholds.freeable_memory_byte
      description = "Freeable memory low"
    }
    connections = {
      metric      = "DatabaseConnections"
      comparison  = "GreaterThanThreshold"
      threshold   = local.thresholds.connections
      description = "Connections high. ArcGIS Server service instances hold connections open."
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "db" {
  for_each = local.alarms

  alarm_name          = "${var.name}-${each.key}"
  alarm_description   = each.value.description
  namespace           = "AWS/RDS"
  metric_name         = each.value.metric
  dimensions          = { DBInstanceIdentifier = aws_db_instance.this.identifier }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  comparison_operator = each.value.comparison
  threshold           = each.value.threshold
  treat_missing_data  = "breaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
  tags                = var.tags
}
