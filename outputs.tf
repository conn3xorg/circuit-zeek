output "log_dir" {
  description = "Directory Zeek writes its logs to on each host. The current logs are in current/."
  value       = "/opt/zeek/logs"
}

output "site_script" {
  description = "Path of the Zeek script the circuit writes on each host, after the package's local.zeek."
  value       = "/opt/zeek/share/zeek/site/conn3x.zeek"
}
