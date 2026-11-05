# circuit-zeek

[![Conn3x grade](https://conn3x.org/circuits/zeek/grade.svg)](https://conn3x.org/circuits/zeek/grade)

A Conn3x circuit that installs the Zeek network security monitor from Zeek's own packages and runs it as a standalone sensor on one interface. Zeek watches the traffic going past and writes down what happened: every connection in `conn.log`, every DNS question and answer in `dns.log`, every HTTP request in `http.log`, the certificates, the software versions, the odd things. When something on your network starts talking to somewhere it shouldn't, those logs are how you find out what, when and to whom.

Setting Zeek up by hand means a repository and its key, three config files under `/opt/zeek/etc`, a choice of log format, a crontab line and something to start it at boot. This circuit does all of that from a handful of inputs, turns JSON logs on so they go straight into whatever you search logs with, and checks every change with `zeekctl check` before the running Zeek sees it.

It runs on Ubuntu 24.04 and Debian 13. Zeek doesn't build packages for Rocky Linux or Fedora 45; see [Distributions](#distributions).

## Usage

```hcl
module "zeek" {
  source = "github.com/conn3xorg/circuit-zeek?ref=v0.1.2"

  hosts                = { sensor1 = "203.0.113.10" }
  ssh_private_key_file = "~/.ssh/id_ed25519"

  interface       = "ens4"
  networks        = ["192.168.1.0/24", "2001:db8:1::/48"]
  log_expire_days = 90

  local_zeek = <<-EOT
    @load policy/protocols/conn/mac-logging
    @load policy/protocols/ssl/heartbleed
  EOT
}
```

Then run `conn3x init` and `conn3x apply`. A second `conn3x plan` says `No changes.` The logs are in `/opt/zeek/logs/current` on the host:

```sh
ssh root@203.0.113.10 tail -f /opt/zeek/logs/current/conn.log
```

`interface` is where Zeek listens. On a host that only watches its own traffic, that's its main interface. On a dedicated sensor, it's the one plugged into a switch's mirror port or a network tap, and that interface doesn't need an address. When hosts name their interfaces differently, give each host object its own `interface`.

`networks` tells Zeek which addresses are yours, which sets `local_orig` and `local_resp` in `conn.log` and decides what counts as inbound and outbound. Private address space, such as `10.0.0.0/8` and `192.168.0.0/16`, is local without being listed; list your public ranges.

For hosts created in the same plan, pass host objects with the host key you generated, and their distribution in `os`, since the circuit picks Zeek's repository by distribution and can't ask a host that doesn't exist yet. Set `os` as well when you put `depends_on` on this module.

```hcl
hosts = {
  for name, d in digitalocean_droplet.sensor : name => {
    address   = d.ipv4_address
    host_key  = tls_private_key.host[name].public_key_openssh
    os        = "ubuntu"
    interface = "eth0"
  }
}
```

To try it on a throwaway container first, see [examples/local](examples/local).

### Watching the host's own traffic

Most network cards fill in TCP and UDP checksums in hardware, after Zeek has already seen the packet. On a host watching its own traffic, Zeek then sees the outgoing packets with bad checksums and drops them, and `reporter.log` says `Your interface is likely receiving invalid TCP and UDP checksums`. On DigitalOcean droplets and in containers, that left the host's own HTTP requests out of `http.log` entirely. Tell Zeek to skip the check:

```hcl
local_zeek = "redef ignore_checksums = T;"
```

A sensor on a mirror port or tap sees the checksums that went over the wire, and doesn't need it.

## What it does

On each host, in order:

1. Adds Zeek's repository on the openSUSE Build Service, `download.opensuse.org/repositories/security:/zeek/`, for the host's release (`xUbuntu_24.04` or `Debian_13`), with its signing key from [files/zeek-obs.asc](files/zeek-obs.asc). That key expires on 2 December 2026; see [The signing key](#the-signing-key).
2. Installs `zeekctl-9.0`, which pulls in `zeek-9.0-core`. Both live under `/opt/zeek`. The `zeek-9.0` package would add the compilers and headers for building plugins, which a sensor doesn't need.
3. Writes `/opt/zeek/etc/node.cfg` with one standalone node on your interface, `/opt/zeek/etc/networks.cfg` from `networks`, and `/opt/zeek/etc/zeekctl.cfg` with the package's settings and your log retention. Then writes `/opt/zeek/share/zeek/site/conn3x.zeek`, which loads `policy/tuning/json-logs` and your `local_zeek` lines. zeekctl loads it after the package's own `local.zeek`, which stays as shipped.
4. Runs `zeekctl check`, and only if it passes, `zeekctl install`, which copies the config and scripts to where the running Zeek reads them. A script error stops the apply with Zeek's own message, such as `error in /opt/zeek/share/zeek/site/conn3x.zeek, line 4: syntax error`, and the running Zeek carries on with the last config that passed. The next apply runs the check again.
5. Installs a `zeek.service` unit that runs `zeekctl start` and `zeekctl stop`, starts it now and at boot, and restarts it after each install. The packages don't ship a unit of their own for zeekctl.
6. Installs `zeek-cron.timer`, which runs `zeekctl cron` every five minutes, as Zeek's docs suggest for a crontab line. That restarts Zeek if it crashed, deletes logs past their expiry, and checks free disk space.

Zeek writes the current logs to `/opt/zeek/logs/current` and, every `log_rotation_interval` seconds, moves them into a dated directory such as `/opt/zeek/logs/2026-10-29`, compressed. `zeekctl cron` deletes those directories' logs once they're older than `log_expire_days`. The default keeps 30 days; set `0` to keep them all and manage the disk yourself.

Zeek runs as root, as zeekctl starts it. zeekctl's mail reports are off, since most hosts have no mail set up.

### The signing key

The openSUSE Build Service signs Zeek's repository with a key that expires on 2 December 2026. The service usually extends a project key shortly before it runs out, but the circuit carries its own copy, and once that copy's date passes, apt refuses the repository and the package step fails. Update to a release of this circuit carrying the extended key before then. Hosts that already have Zeek keep running it either way. Check the date with:

```sh
gpg --show-keys files/zeek-obs.asc
```

### Zeek versions

`zeek_series` picks the release line, `9.0` by default. Zeek's X.0 lines are its long-term support releases; 9.0 came out in August 2026 and 9.0.1 is current. The host gets the newest release on the line and `apt upgrade` keeps it there, moving to 9.0.2 and so on but never to 9.1 or 10.0. The repository keeps only the newest release of each line, so there's no pinning an exact one.

After an `apt upgrade` brings a new Zeek, `zeekctl status` says `new zeek version detected`. Run `zeekctl deploy` on the host to restart onto it. Changing `zeek_series` runs the check, install and restart for you.

### What it doesn't do

- It runs one standalone Zeek. It doesn't set up a cluster with workers, proxies and a logger, or AF_PACKET load balancing across cores. Size the host for the traffic you point it at.
- It doesn't install Zeek packages with `zkg`, ship logs anywhere or set up intel feeds. Load scripts that ship with Zeek through `local_zeek`.
- It doesn't configure the interface, turn off NIC offloading or set up a mirror port.
- Deleting the module leaves Zeek installed and running with the last config.

## Inputs

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `hosts` | any | Required | Hosts to configure, by name. Each value is an address, such as `"203.0.113.10"`, or a host object such as `{ address = "203.0.113.10", host_key = "ssh-ed25519 AAAA..." }`. A host object can also set `user`, `port`, `private_key_file`, `jump_hosts`, `os`, the distribution's ID, `debian` or `ubuntu`, which a host created in the same plan needs, and `interface`, which overrides `interface` for that host. |
| `ssh_user` | string | `"root"` | User to log in as. |
| `ssh_port` | number | `22` | SSH port. |
| `ssh_private_key_file` | string | `null` | Path to a private key. When null, Conn3x uses the SSH agent. |
| `ssh_known_hosts_file` | string | `null` | known_hosts file to check host keys against. When null, `~/.ssh/known_hosts`. Not used for a host object with `host_key`. |
| `ssh_become` | bool | `false` | Run commands as root through sudo. Set it when `ssh_user` isn't root. |
| `zeek_series` | string | `"9.0"` | Zeek release line to install, such as `"9.0"`. |
| `interface` | string | `"eth0"` | Network interface Zeek listens on. |
| `networks` | list(string) | `[]` | Networks Zeek treats as local, in CIDR notation, such as `["192.168.1.0/24", "2001:db8::/32"]`. Private address space is local without being listed. |
| `json_logs` | bool | `true` | Write logs as JSON, one object per line. `false` keeps Zeek's tab-separated format. |
| `log_rotation_interval` | number | `3600` | Seconds between log rotations. `0` turns rotation off. |
| `log_expire_days` | number | `30` | Days rotated logs are kept before `zeekctl cron` deletes them. `0` keeps them for good. |
| `local_zeek` | string | `""` | Zeek script lines loaded after the package's `local.zeek`, such as `"@load policy/protocols/conn/mac-logging"`. |

## Outputs

| Name | Description |
| --- | --- |
| `log_dir` | Directory Zeek writes its logs to, `/opt/zeek/logs`. The current logs are in `current/`. |
| `site_script` | Path of the script the circuit writes, `/opt/zeek/share/zeek/site/conn3x.zeek`. |

## Distributions

| Distribution | Supported | Why |
| --- | --- | --- |
| Ubuntu 24.04 | Yes | `xUbuntu_24.04`, amd64 and arm64. |
| Debian 13 | Yes | `Debian_13`, amd64 and arm64. |
| Rocky Linux 10 | No | Zeek's repositories have no Enterprise Linux builds, for Rocky Linux, AlmaLinux or RHEL. |
| Fedora 45 | No | Zeek's repositories have Fedora 43, 44 and Rawhide, and no Fedora 45 yet, as of 29 October 2026. |

The circuit stops at plan time on any other distribution, with a message saying so.

## Requirements

Requires Conn3x v0.6.9 or later and systemd on each host, with access to `download.opensuse.org`. Zeek used about 260 MB of memory on an idle 2 GB droplet; give a busier sensor more.

## Tested on

Ubuntu 24.04 and Debian 13. CI applies [examples/local](examples/local) to each on amd64, checks the second plan has no changes and that `zeek` and `zeek-cron.timer` are active, then makes a DNS lookup and an HTTP request from inside the container and checks `zeekctl status` shows Zeek running, the lookup is in `dns.log`, the request is in `http.log`, its connection is in `conn.log`, and all three are valid JSON. The container gets `NET_RAW` and no other added privilege.

By hand on the same containers on arm64: the same checks passed; a syntax error in `local_zeek` stopped the apply at `zeekctl check` while the running Zeek kept its process and its installed scripts; Zeek killed with `SIGKILL` came back on the next `zeek-cron.service` run and stayed up after the unit finished; and on Debian 13, after a container restart, Zeek came back and the plan had no changes. Without `ignore_checksums`, the container's own HTTP request didn't reach `http.log`.

On Ubuntu 24.04 and Debian 13 droplets (1 vCPU, 2 GB) with Zeek 9.0.1 on `eth0`, the same DNS, HTTP and connection checks passed, with `ignore_checksums` set and the DNS lookup sent to a public resolver, since the droplets' own resolver answers on the private interface. After a reboot, Zeek came back on both, the timer ran `zeekctl cron`, and the plan had no changes.

## License

MPL-2.0. See [LICENSE](LICENSE). Zeek itself is BSD-3-Clause.
