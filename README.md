# Arcadex

## Run locally

Requires Node.js 18 or newer.

```powershell
npm start
```

Open `http://localhost:8787/`. The backend serves the existing one-file client, stores account data in `highway-data.json`, and stores hashed Remember me sessions in `highway-data.json.sessions` (all created with restricted permissions). Set `PORT`, `HIGHWAY_DATA_FILE`, and `HIGHWAY_SESSION_FILE` in the deployment environment as needed. Keep both data files on persistent storage if Remember me should survive server restarts.

Accounts use a unique username and password. New passwords must be 5-10 characters to match the current product requirement. Passwords are hashed with Node.js `scrypt`; sessions are HttpOnly cookies. The client does not contain database credentials or private keys.

For production, deploy behind HTTPS and replace the file-backed database with a transactional database plus a shared session store. The current server-side score cap rejects impossible aggregate submissions, but authoritative anti-cheat requires server-recorded gameplay telemetry or a trusted game server.


## Production deployment

The browser client and API must be reachable from the deployment. If they are served from the same domain, no extra setting is required. If the frontend and API use different HTTPS origins, set:

- `PUBLIC_ORIGIN=https://your-game-domain.example`
- `API_ORIGIN=https://your-api-domain.example`
- `NODE_ENV=production`

Then set `window.HIGHWAY_RACER_API_URL` before the main client script to `https://your-api-domain.example/api`. The server will enable credentialed CORS for the configured frontend origin and use a cross-site secure session cookie.

Do not deploy `index.html` as a static-only site while expecting `/api/accounts`, `/api/session`, or `/api/me` to work. Those endpoints require the Node server (or an equivalent serverless backend).
