# MyTail

MyTail is a transparent, consent-gated remote-support system. A privileged
cross-platform agent enrolls with the broker, but administrative access stays
disabled until the customer approves a named operator, reason, and duration.

During an approved window the agent:

- holds the operator public key in memory only;
- exposes its embedded SSH server only on `127.0.0.1:22222`;
- creates an outbound reverse SSH tunnel through Cloudflare over HTTPS;
- runs the approved shell with the installed service privileges (root/SYSTEM);
- closes the tunnel and revokes the key on pause, rejection, broker failure, or expiry.

There is no shared customer key and no permanent operator entry in
`authorized_keys`. Each device has a unique relay key restricted server-side to
one loopback reverse-forward port. Both relay and device host keys are pinned.

## Installation transparency

The Windows installer requires an explicit checkbox before elevation and shows
the exact service, key, network, and SYSTEM-level changes. Linux package metadata
and post-install output describe the root service and connectivity test. The
macOS package installs a visible root LaunchDaemon and opens the local dashboard.
All platforms bundle `cloudflared`; Windows installs OpenSSH Client when absent.

After enrollment, installation tests the broker HTTPS endpoint, Cloudflare relay,
device-key authentication, and loopback SSH endpoint. The local dashboard at
`http://127.0.0.1:8787` shows connectivity, active access, operator, reason, and
expiration, and lets the customer pause the agent.

Windows and macOS alpha packages are currently unsigned/not notarized and will
show the operating system's standard warning.

## Development

```bash
go test ./...
go vet ./...
python3 -m unittest discover -s tests -v
```

The production broker uses `infrastructure/docker-compose.prod.yml`. Required
secrets are mounted from `/etc/mytail/secrets`; relay keys and operator known
hosts are written to their dedicated host directories.
