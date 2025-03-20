variable "function_name" {
  description = "Lambda function name"
  type        = string
}

variable "kv_name" {
  description = "Secret that stores a kv pair in the form of Key:IV - used by client & server"
  type        = string
}

variable "root_ca_url" {
  description = "URL for the Root CA1"
  type        = string
}

variable "region" {
  description = "The region the tf runs in"
  type        = string
}
