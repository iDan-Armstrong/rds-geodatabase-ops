variable "region" {
  type    = string
  default = "us-east-1"
}

variable "engine_version" {
  description = "Check the Esri matrix first: rdsops compat --engine-version X.Y"
  type        = string
  default     = "17.7"
}

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "client_security_group_ids" {
  description = "Security group of the EC2 machine running ArcGIS Pro or ArcGIS Server."
  type        = list(string)
  default     = []
}

variable "owner" {
  type = string
}
