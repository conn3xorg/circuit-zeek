variable "port" {
  type    = number
  default = 2293
}

module "zeek" {
  source = "../.."

  hosts                = { box = "127.0.0.1" }
  ssh_port             = var.port
  ssh_private_key_file = "./id_ed25519"
  ssh_known_hosts_file = "./known_hosts"

  interface       = "eth0"
  networks        = ["10.88.0.0/16"]
  log_expire_days = 7

  # A container's virtual interface hands Zeek packets before the checksums
  # are filled in, and Zeek drops packets with bad checksums.
  local_zeek = <<-EOT
    redef ignore_checksums = T;
    @load policy/protocols/conn/mac-logging
  EOT
}

# curl, to make some traffic for Zeek to see. It runs after the module, so
# its package run doesn't overlap the module's.
circuit "tools" {
  hosts = { box = "127.0.0.1" }

  ssh {
    user             = "root"
    port             = var.port
    private_key_file = "./id_ed25519"
    known_hosts_file = "./known_hosts"
  }

  step "curl" {
    package {
      name = "curl"
    }
    depends_on = [module.zeek]
  }
}
