output "instance_identifier" {
  description = "DB instance identifier, the value rdsops takes as --instance."
  value       = aws_db_instance.this.identifier
}

output "instance_arn" {
  value = aws_db_instance.this.arn
}

output "endpoint" {
  description = "host:port for ArcGIS database connections (.sde)."
  value       = aws_db_instance.this.endpoint
}

output "address" {
  value = aws_db_instance.this.address
}

output "port" {
  value = aws_db_instance.this.port
}

output "database_name" {
  value = aws_db_instance.this.db_name
}

output "master_user_secret_arn" {
  description = "Secrets Manager secret holding the RDS master password. Read it with IAM, never copy it into tfvars."
  value       = aws_db_instance.this.master_user_secret[0].secret_arn
}

output "kms_key_arn" {
  value = aws_kms_key.db.arn
}

output "security_group_id" {
  description = "Attach additional ingress rules to this group, or pass client groups in allowed_security_group_ids."
  value       = aws_security_group.db.id
}

output "parameter_group_name" {
  description = "Baseline for `rdsops drift`."
  value       = aws_db_parameter_group.this.name
}
