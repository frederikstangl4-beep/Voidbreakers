# Voidbreakers server

Accounts, cloud profiles, leaderboards, cloud saves and room signaling for the
single-file game. Pure Python (3.10+) plus the `websockets` package.

## Run locally

```sh
python3 server.py --host 127.0.0.1 --port 8765 --db data/voidbreakers.db
```

Then in the game: **Account** -> server `ws://localhost:8765` -> create account.

## Admin

```sh
python3 server.py --db data/voidbreakers.db --create-user Alice --password 'hunter2hunter2'
python3 server.py --db data/voidbreakers.db --reset-password Alice --password 'newpassword1'
```

## Tests

```sh
python3 tests/test_client.py     # starts a throwaway server on :8791
```

## Public deployment

1. Copy this folder to the server (e.g. `/opt/voidbreakers-server`).
2. Run as `voidbreakers.service` (see `deploy/`), listening on 127.0.0.1:8765.
3. Put Caddy in front for TLS: `deploy/Caddyfile` (gives `wss://your-domain/ws`).
4. Serve the game over https next to it; the client uses `wss://<host>/ws` automatically
   when the page is https, or the server field can be set by hand.
5. Schedule `deploy/voidbreakers-backup.sh` daily.

## Protocol (JSON over WebSocket)

Client -> server: `register`, `login`, `resume`, `logout`, `password.change`, `recover`,
`profile.get`, `profile.put`, `save.list/push/pull/delete`, `board.top/submit`,
`room.create/join/leave/signal/list`, `chat.send`, `ping`.

Server -> client: `welcome`, `session`, `profile`, `saves`, `save`, `board`, `ok`,
`error{code,message}`, `room.created/joined/peer/signal`, `chat`, `pong`.

Boards: `waves`, `rift`, `bossrush`, `elo`, `ghost` (server keeps each player's best).
Passwords: scrypt (n=2^14, r=8, p=1) with per-user salt. Sessions: 32-byte tokens,
hashed at rest, 30-day expiry. Recovery codes are shown once at sign-up.
