# Facts give each host's distribution and release, which pick the Zeek
# repository to use. Zeek's packages are built for Debian and Ubuntu only
# among the distributions this circuit supports.
data "conn3x_host" "facts" {
  for_each = var.hosts

  ssh {
    host             = try(each.value.address, each.value)
    host_key         = try(each.value.host_key, null)
    user             = try(each.value.user, var.ssh_user)
    port             = try(each.value.port, var.ssh_port)
    private_key_file = try(each.value.private_key_file, var.ssh_private_key_file)
    jump_hosts       = try(each.value.jump_hosts, null)
    known_hosts_file = var.ssh_known_hosts_file
  }

  lifecycle {
    postcondition {
      condition     = try(each.value.os, self.os_id) == self.os_id
      error_message = "Host ${each.key} is ${self.os_id}, not the ${try(each.value.os, "")} its os says."
    }

    postcondition {
      condition     = contains(["debian", "ubuntu"], self.os_id)
      error_message = "Host ${each.key} is ${self.os_id}. Zeek's packages are built for Debian and Ubuntu, so this circuit supports only those."
    }
  }
}

locals {
  # A host object's os stands in for the facts of a host created in the
  # same plan, which can't be read until it exists.
  os = { for name, h in var.hosts : name => try(h.os, data.conn3x_host.facts[name].os_id) }

  # The openSUSE Build Service names each repository after the release it's
  # built for, such as xUbuntu_24.04 or Debian_13.
  repo_url = { for name, h in var.hosts : name => format(
    "https://download.opensuse.org/repositories/security:/zeek/%s_%s/",
    local.os[name] == "ubuntu" ? "xUbuntu" : "Debian",
    data.conn3x_host.facts[name].os_version,
  ) }

  zeekctl = "/opt/zeek/bin/zeekctl"

  # Installed packages from a Zeek release line other than zeek_series,
  # such as zeek-8.0-core and zeekctl-8.0 when the series is 9.0. Each
  # line installs into /opt/zeek and they don't conflict with each other
  # in dpkg, so the old one has to go before the new one can install.
  other_series = join(" ", [
    "dpkg-query -W -f '$${Package} $${db:Status-Abbrev}\\n'",
    "| awk -v s=${var.zeek_series} '$2 ~ /^ii/ && $1 ~ /^(zeek|zeekctl|libbroker)-/ && match($1, /-[0-9]+[.][0-9]+(-|$)/) { v = substr($1, RSTART + 1, RLENGTH - 1); sub(/-$/, \"\", v); if (v != s) print $1 }'",
  ])

  node_cfg = { for name, h in var.hosts : name => <<-EOT
    # Written by Conn3x. Changes here are overwritten on the next apply.
    [zeek]
    type=standalone
    host=localhost
    interface=${try(h.interface, var.interface)}
    EOT
  }

  networks_cfg = join("", concat(
    ["# Written by Conn3x. Changes here are overwritten on the next apply.\n"],
    [for n in var.networks : "${n}\n"],
  ))

  # The package's defaults, with retention from the inputs. SendMail is
  # blank, so zeekctl doesn't try to mail reports through a sendmail the
  # host may not have. MailTo is set anyway: unset, it comes from $USER,
  # which differs between SSH and systemd, and zeekctl then says its
  # config changed when it didn't.
  expire      = var.log_expire_days == 0 ? "0" : "${var.log_expire_days}day"
  zeekctl_cfg = <<-EOT
    # Written by Conn3x. Changes here are overwritten on the next apply.
    SendMail =
    MailTo = root
    MinDiskSpace = 5
    LogRotationInterval = ${var.log_rotation_interval}
    LogExpireInterval = ${local.expire}
    StatsLogEnable = 1
    StatsLogExpireInterval = ${var.log_expire_days}
    CrashExpireInterval = ${var.log_expire_days}
    StatusCmdShowAll = 0
    SitePolicyScripts = local.zeek conn3x.zeek
    LogDir = /opt/zeek/logs
    SpoolDir = /opt/zeek/spool
    BrokerDBDir = /opt/zeek/spool/brokerstore
    FileExtractDir = /opt/zeek/spool/extract_files
    CfgDir = /opt/zeek/etc
    MetricsAddress = 127.0.0.1
    MetricsPort = 9991
    EOT

  # Loaded after the package's own local.zeek, which stays as shipped.
  site_zeek = join("\n", compact([
    "# Written by Conn3x. Changes here are overwritten on the next apply.",
    var.json_logs ? "@load policy/tuning/json-logs" : "",
    trimspace(var.local_zeek),
  ]))
}

circuit "zeek" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  # Zeek's own repository on the openSUSE Build Service, a flat repository
  # per release. Its signing key, in files/zeek-obs.asc, expires on
  # 2 December 2026.
  step "repo" {
    repository {
      name   = "zeek"
      url    = local.repo_url[each.key]
      key    = file("${path.module}/files/zeek-obs.asc")
      suites = ["/"]
    }
  }

  # Moving to another zeek_series: stops Zeek and removes the old line.
  # remove, not purge, so the config stays, and /opt/zeek/logs and
  # /opt/zeek/spool aren't the packages' to remove. The steps below then
  # install the new line, write the config again and restart Zeek.
  step "old_series" {
    command {
      command = "old=$(${local.other_series}) && { systemctl stop zeek 2>/dev/null || true; } && DEBIAN_FRONTEND=noninteractive apt-get remove -y $old"
      unless  = "[ -z \"$(${local.other_series})\" ]"
    }
  }

  # zeekctl-<series> pulls in Zeek itself and stays on that release line.
  # The zeek-<series> package would add compilers and headers for building
  # plugins, which a sensor doesn't need.
  step "package" {
    package {
      name = "zeekctl-${var.zeek_series}"
    }
  }

  # Group zeek and mode 0664 match what the package's postinst sets on each
  # upgrade, so an upgrade doesn't show up as drift.
  step "node" {
    file {
      path    = "/opt/zeek/etc/node.cfg"
      content = local.node_cfg[each.key]
      group   = "zeek"
      mode    = "0664"
    }
  }

  step "networks" {
    file {
      path    = "/opt/zeek/etc/networks.cfg"
      content = local.networks_cfg
      group   = "zeek"
      mode    = "0664"
    }
  }

  step "zeekctl_cfg" {
    file {
      path    = "/opt/zeek/etc/zeekctl.cfg"
      content = local.zeekctl_cfg
      group   = "zeek"
      mode    = "0664"
    }
  }

  step "site" {
    file {
      path    = "/opt/zeek/share/zeek/site/conn3x.zeek"
      content = local.site_zeek
      group   = "zeek"
      mode    = "0664"
    }
  }

  # zeekctl install copies the config and scripts to where the running
  # Zeek reads them, and only after zeekctl check passes, so a script
  # error stops the apply and the running Zeek carries on with the last
  # good config. The restart then runs it under systemd.
  step "install" {
    command {
      command = "${local.zeekctl} check && ${local.zeekctl} install"
      triggers = {
        series   = var.zeek_series
        node     = conn3x_file.zeek__node[each.key].revision
        networks = conn3x_file.zeek__networks[each.key].revision
        zeekctl  = conn3x_file.zeek__zeekctl_cfg[each.key].revision
        site     = conn3x_file.zeek__site[each.key].revision
      }
    }
    notify = [handler.restart]
  }

  step "unit" {
    file {
      path    = "/etc/systemd/system/zeek.service"
      content = file("${path.module}/files/zeek.service")
    }
  }

  step "running" {
    service {
      name    = "zeek"
      state   = "started"
      enabled = true
    }
  }

  step "cron_unit" {
    file {
      path    = "/etc/systemd/system/zeek-cron.service"
      content = file("${path.module}/files/zeek-cron.service")
    }
  }

  step "cron_timer" {
    file {
      path    = "/etc/systemd/system/zeek-cron.timer"
      content = file("${path.module}/files/zeek-cron.timer")
    }
  }

  step "cron" {
    service {
      name    = "zeek-cron.timer"
      state   = "started"
      enabled = true
    }
  }

  handler "restart" {
    service {
      name   = "zeek"
      action = "restart"
    }
  }
}
