# Local example

Applies circuit-zeek to a throwaway Ubuntu 24.04 container with systemd, then installs curl so you can make some traffic for Zeek to see. You need Conn3x and Podman.

Zeek captures packets on the container's `eth0`, which needs the `NET_RAW` capability. `up.sh` adds that and nothing else, which is simplest with rootful Podman. On a Mac, use the Podman machine's root connection. On Linux, use `sudo podman`:

```sh
export CONTAINER_CONNECTION=podman-machine-default-root   # macOS
export PODMAN="sudo podman"                               # Linux
./up.sh
conn3x init
conn3x apply
conn3x plan
```

The second plan says `No changes.` To make some traffic and watch Zeek log it:

```sh
ssh -p 2293 -i id_ed25519 -o UserKnownHostsFile=known_hosts root@127.0.0.1
curl -s http://example.com/ >/dev/null
/opt/zeek/bin/zeekctl status
tail -n 2 /opt/zeek/logs/current/http.log /opt/zeek/logs/current/dns.log
```

The example sets `redef ignore_checksums = T;`. The container's network interface hands Zeek packets before their checksums are filled in, and without it Zeek drops the container's own traffic.

`up.sh` listens on `127.0.0.1:2293`. Set `PORT` to use another port, and pass the same port to Conn3x with `-var port=PORT`. Set `CONTAINERFILE` to test Debian 13 with the image in Conn3x's `test/images`, which CI uses.

`./down.sh` removes the container, its volumes, the key and the state.
