variable "config" {
  type = map(string)
}

locals {
  config = jsondecode(file("config.json"))
}

variable "function_name" {
  description = "Lambda function name"
  type        = string
  default     = local.config["function_name"]
}

variable "kv_name" {
  description = "Secret that stores a kv pair in the form of Key:IV - used by client & server"
  type        = string
  default     = local.config["kv_name"]
}

variable "root_ca_url" {
  description = "URL for the Root CA1"
  type        = string
  default     = local.config["kv_name"]
}

variable "region" {
  description = "The region the tf runs in"
  type        = string
  default     = local.config["region"]
}