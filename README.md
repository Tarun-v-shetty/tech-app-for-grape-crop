# Vineyard Fieldbook backend

## Run locally

Python 3.9 or newer is required; the backend uses only Python's standard library.

1. In this folder, create the first administrator account:

   ```powershell
   python server.py --create-admin admin@example.com
   ```

   Enter a display name and a password of at least 12 characters when prompted.
2. Start the application:

   ```powershell
   python server.py
   ```
3. Open <http://127.0.0.1:8000/> in a browser. Create farmer accounts from the sign-in screen. An administrator can promote verified accounts to advisor or administrator in the User access panel.

The SQLite database is created as `grape_app.sqlite3` in this folder. Set `GRAPE_DB_PATH` to use another database location. `GRAPE_HOST` and `GRAPE_PORT` can change the bind address and port; the server binds to `127.0.0.1:8000` by default.

## Free Render demo

This repository includes a `render.yaml` Blueprint for a free Render web service. From the repository owner's signed-in browser, open <https://render.com/deploy?repo=https%3A%2F%2Fgithub.com%2FTarun-v-shetty%2Ftech-app-for-grape-crop>, connect GitHub if prompted, then choose **Apply** to create the service. Render assigns its public `onrender.com` address after the build and `/health` check succeed.

The free demo stores its SQLite database at `/tmp/grape_app.sqlite3`. Free-instance files are ephemeral, so accounts, prices, and field records can be lost when the instance restarts or redeploys. The free instance may also sleep when unused and take a short time to start on the next visit. Do not use this demo for sensitive or important records. Durable storage is not configured.

Render supplies the listening port through `PORT`. The server keeps its localhost/port 8000 defaults for local development. Session cookies include `Secure` when requests are forwarded over HTTPS.

## Roles

- **Farmer:** create and view their own symptom checks and weather plans; view shared market prices; create and delete their own prices.
- **Advisor:** everything a farmer can do, plus view field records from all accounts.
- **Administrator:** everything an advisor can do, plus manage account roles and delete any price entry.

Role permissions are enforced by the backend, not just hidden in the browser. Registration always creates a farmer account. Changing an account's role invalidates its existing sessions. The final administrator cannot be demoted.

## Data and deployment

Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes. Sessions use random, opaque tokens in `HttpOnly`, `SameSite=Strict` cookies. Field photos stay in the browser and are not uploaded.

This built-in HTTP server is intended for local use and development. Do not expose it to the public internet as-is. A production deployment needs HTTPS, secure cookie settings, an appropriately configured reverse proxy, database backups, and an account verification process before granting elevated roles.

## Tests

Run the API and permission tests with:

```powershell
python -m unittest discover -s tests -v
```
