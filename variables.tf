variable "hosts" {
  type        = any
  description = "Hosts to configure: a map of names to addresses, or to host objects with an address and optional host_key, user, port, private_key_file, jump_hosts, os or interface."

  validation {
    condition     = alltrue([for h in var.hosts : contains(["debian", "ubuntu"], try(h.os, "debian"))])
    error_message = "A host object's os must be debian or ubuntu. Zeek's packages aren't built for the other distributions Conn3x supports."
  }

  validation {
    condition     = alltrue([for h in var.hosts : can(regex("^[A-Za-z0-9_.:@-]+$", try(h.interface, "eth0")))])
    error_message = "A host object's interface is a network interface name, such as \"eth0\" or \"ens3\"."
  }
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "User to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "known_hosts file to check host keys against. When null, ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run commands as root through sudo."
}

variable "zeek_series" {
  type        = string
  default     = "9.0"
  description = "Zeek release line to install, such as \"9.0\". The host gets the newest release on that line. X.0 lines are Zeek's long-term support releases."

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+$", var.zeek_series))
    error_message = "zeek_series is a release line such as \"9.0\"."
  }
}

variable "interface" {
  type        = string
  default     = "eth0"
  description = "Network interface Zeek listens on. A host object's interface overrides it for that host."

  validation {
    condition     = can(regex("^[A-Za-z0-9_.:@-]+$", var.interface))
    error_message = "interface is a network interface name, such as \"eth0\" or \"ens3\"."
  }
}

variable "networks" {
  type        = list(string)
  default     = []
  description = "Networks Zeek treats as local, in CIDR notation, such as [\"192.168.1.0/24\"]. Private address space counts as local without being listed."

  validation {
    condition     = alltrue([for n in var.networks : can(cidrhost(n, 0)) && strcontains(n, "/")])
    error_message = "Each of networks must be a CIDR network, such as \"192.168.1.0/24\" or \"2001:db8::/32\"."
  }
}

variable "json_logs" {
  type        = bool
  default     = true
  description = "Write Zeek's logs as JSON, one object per line, instead of tab-separated values."
}

variable "log_rotation_interval" {
  type        = number
  default     = 3600
  description = "Seconds between log rotations. Each rotation moves the current logs into a dated directory under /opt/zeek/logs. 0 turns rotation off."

  validation {
    condition     = var.log_rotation_interval >= 0 && floor(var.log_rotation_interval) == var.log_rotation_interval
    error_message = "log_rotation_interval must be a whole number of seconds, 0 or more."
  }
}

variable "log_expire_days" {
  type        = number
  default     = 30
  description = "Days rotated logs are kept before zeekctl cron deletes them. 0 keeps them for good."

  validation {
    condition     = var.log_expire_days >= 0 && floor(var.log_expire_days) == var.log_expire_days
    error_message = "log_expire_days must be a whole number of days, 0 or more."
  }
}

variable "local_zeek" {
  type        = string
  default     = ""
  description = "Zeek script lines loaded after the package's local.zeek, such as \"@load policy/protocols/conn/mac-logging\"."
}
