# Run on the host. Makes a DNS lookup and an HTTP request, then checks
# Zeek logged both, as JSON, on eth0: the lookup in dns.log, the request
# in http.log, and its connection in conn.log.
set -eu
/opt/zeek/bin/zeekctl status | grep -Eq '^zeek +standalone +localhost +running'
getent hosts example.org
curl -sSf -o /dev/null http://example.com/
logs=/opt/zeek/logs/current
for _ in $(seq 30); do
  uid=$(grep -h '"host":"example.com"' $logs/http.log 2>/dev/null | sed -n 's/.*"uid":"\([^"]*\)".*/\1/p' | head -n 1)
  if [ -n "$uid" ] && grep -q "\"uid\":\"$uid\"" $logs/conn.log 2>/dev/null \
    && grep -q '"query":"example.org"' $logs/dns.log 2>/dev/null; then
    for f in conn dns http; do
      python3 -c 'import json, sys; [json.loads(l) for l in open(sys.argv[1])]' $logs/$f.log
    done
    exit 0
  fi
  sleep 1
done
exit 1
