# Render deployment

This deployment runs the Rust API on a Render Free Web Service. It uses the
existing Neon PostgreSQL database. Render must not receive the Android build or
the local vault database.

## Before deployment

1. Put this repository in a private GitHub repository.
2. Keep the Neon connection string out of Git.
3. Keep Firebase service-account JSON files out of Git.
4. Confirm that the repository-root `render.yaml` file is present.

## Create the service

1. Open the Render dashboard.
2. Select **New**, then **Blueprint**.
3. Connect the private GitHub repository.
4. Select the `main` branch.
5. When Render requests `DATABASE_URL`, paste the Neon pooled connection
   string.
6. Create the Blueprint.

The Blueprint creates `SERVER_KEY`. Do not replace that value after accounts
exist. A changed key changes fabricated prelogin salts and weakens account
enumeration resistance.

Render supplies `PORT`. The server binds `0.0.0.0:<PORT>`. Local development
continues to bind `127.0.0.1:8080` when neither `BIND` nor `PORT` exists.

The free service uses five PostgreSQL pool connections. This limit reduces
connection use against the Neon Free database.

## Verify the deployment

Open this address after Render reports a healthy deployment:

```text
https://<render-service-host>/v1/health
```

The response must be:

```text
ok
```

The server runs database migrations during startup. Do not create the server
tables manually in Neon.

## Features that remain disabled

Do not set `FCM_PROJECT_ID` until Google Application Default Credentials are
available to the service. The server rejects startup when the project ID exists
without credentials.

Do not set the three `WEBAUTHN_*` variables until the final HTTPS domain and
Digital Asset Links file are configured.

## Free-service limitation

Render can stop a Free Web Service after 15 minutes without traffic. The first
request after that stop can take approximately one minute. Use the free service
for development and beta testing. It does not provide production availability.
