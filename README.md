# MyTail

MyTail is a consent broker for remote support on customer Windows machines. It is intentionally scoped to the safe control-plane pieces:

- operator login
- machine enrollment
- access requests with customer-facing approval links
- customer-selected access duration
- audit history
- machine check-in API for a visible local agent

It does not implement a hidden admin agent or an always-on privileged backdoor.

The public, static explanation and download landing page lives in `docs/`. It is
the only component intended for deployment at `https://suporte.hirableaiagents.com`;
the consent broker is not exposed at that hostname.

## MVP flow

1. Install a visible Windows service and consent UI on the customer machine.
2. Enroll the machine in MyTail and store the returned `machine_token` in the agent config.
3. An operator requests access for a machine with a reason and requested duration.
4. The customer opens the approval link, verifies the consent code, and chooses how long to allow access.
5. The local agent polls `/api/agent/checkin`, sees the approved window, and can enable the chosen support channel only for that time box.
6. When the grant expires, the agent must remove access automatically.

## Local run

```bash
export OPERATOR_EMAIL=you@example.com
export OPERATOR_PASSWORD='change-this'
export SESSION_SECRET='change-this-too'
python3 server.py
```

Open `http://127.0.0.1:8080`.

## Environment

- `PORT`
- `APP_URL`
- `SESSION_SECRET`
- `SESSION_COOKIE_NAME`
- `OPERATOR_EMAIL`
- `OPERATOR_PASSWORD`
- `DEFAULT_ACCESS_DURATIONS`
- `MYTAIL_DB_PATH`

## Deploy shape

The repository includes:

- `Dockerfile`
- `infrastructure/docker-compose.prod.yml`
- `infrastructure/nginx/support.innexo.solutions.conf`
- `infrastructure/deploy.sh`

The deploy script is designed to reuse the VPS information already stored in `../innexo.solutions/.env`.
