# NovaNX

NovaNX is a Nexa.py-native package registry. The web server and blueprints use
Nexa.py, templates use Nexa's NXscript syntax, and the interface uses HTML and
CSS only. Search, theme control, forms, and package pages require no JavaScript.
Supabase Auth handles accounts, PostgREST stores metadata in PostgreSQL, and
private Supabase Storage holds package archives. Registration-time profile
checks and verification use Psycopg 3 with a server-only `DATABASE_URL`; the
Auth trigger remains the sole profile writer.

## Requirements

- Python 3.11 or newer
- Nexa.py 0.5.2 or newer
- Psycopg 3 (installed with the project dependencies)
- A Supabase project with the SQL schema installed

Install the Python application dependencies:

```powershell
python -m pip install -e .
```

Copy `.env.example` to `.env` for local development, or set the variables in
your hosting environment. NovaNX reads `.env` using only the Python standard
library and does not expose the service-role key to templates or browser code.

| Variable | Required | Purpose |
| --- | --- | --- |
| `SUPABASE_URL` | Yes | Supabase project URL |
| `SUPABASE_PUBLISHABLE_KEY` | Yes | Public key used for Supabase Auth and read-only requests (`SUPABASE_ANON_KEY` remains a legacy alias) |
| `SUPABASE_SECRET_KEY` | Publishing/downloads | Server-only key for Storage and privileged writes (`SUPABASE_SERVICE_ROLE_KEY` remains a legacy alias) |
| `DATABASE_URL` | Registration | Server-only PostgreSQL connection URI for the same Supabase project; never expose it to browsers |
| `SESSION_SECRET` | Sign-in | At least 32 random characters used to sign HttpOnly session cookies |
| `SUPABASE_STORAGE_BUCKET` | No | Private package bucket; defaults to `novanx-packages` |
| `PUBLIC_BASE_URL` | Production | Public registry origin used in Nova metadata download URLs |
| `HOST` | No | Nexa bind host; defaults to `127.0.0.1` |
| `PORT` | No | Nexa port; defaults to `3000` |
| `COOKIE_SECURE` | Production | Set to `true` behind HTTPS |
| `MAX_ARCHIVE_SIZE` | No | Upload limit in bytes; maximum is 24 MiB |

Use a cryptographically random session secret, for example:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

## Supabase setup

1. Create a Supabase project.
2. Run [`supabase/schema.sql`](./supabase/schema.sql) in the Supabase SQL editor.
   It creates the profile, package, release, download, and maintainer tables;
   enables row-level security; adds auth and download-count triggers; and
   creates the private `novanx-packages` bucket.
3. If you set `SUPABASE_STORAGE_BUCKET` to a custom name, create a matching
   private bucket in Supabase Storage. Keep bucket access private; NovaNX
   streams archives through the backend.
4. Configure Supabase Auth email confirmation and password policies for your
   deployment. User profiles are created by the database auth trigger.
   Re-run the schema after updates so the trigger enforces unique NovaNX usernames.
5. Set the environment variables above. Do not put the service-role key in
   `.env.example`, a template, or a public browser response.

Registration calls Supabase Auth's `/auth/v1/signup` endpoint with the
publishable key in `apikey` and JSON credentials in the request body; the
opaque `sb_publishable_...` key is not sent as a Bearer JWT. NovaNX checks
username availability using a parameterized Psycopg query before signup.
Supabase Auth creates the Auth user; its `SECURITY DEFINER` trigger creates
the profile using the Auth UUID and rejects a conflicting username. Psycopg
then verifies that exact profile row; it does not write to `auth.users` or
create a second profile.
The trigger is owned by `postgres`, uses a fixed search path, and logs
PostgreSQL SQLSTATE, message, constraint, and trigger context before re-raising
failures. If you have already installed an earlier schema version, re-run
`supabase/schema.sql` to update the trigger. Inspect Supabase's Postgres logs
for `NovaNX profile trigger failed` if Auth reports a profile-creation error.
Run the read-only [`supabase/diagnostics.sql`](./supabase/diagnostics.sql) in
the Supabase SQL editor to inspect the live profile schema, RLS policies,
Auth triggers, function owner, and Auth users missing profiles.
Supabase HTTP errors are also logged with a sanitized upstream message;
passwords, API keys, and email addresses are not logged.

The dashboard loads `public.profiles` by the authenticated Auth UUID and shows
an explicit error if the profile is missing; it does not silently substitute
Auth metadata.

When email confirmation is enabled, Auth can return a user without session
tokens. NovaNX treats that as a successful signup and asks the user to verify
their email. With confirmation disabled, Auth returns a session and NovaNX
signs the browser session cookie.

## Run locally

With the required Nexa.py version installed and environment variables set:

```powershell
python app.py
```

Open `http://127.0.0.1:3000`. If Supabase is not configured, public pages show a
visible configuration notice; authentication, uploads, and downloads remain
unavailable until the backend is configured.

## Deploy

NovaNX uses Nexa.py's `NXserver` as its WSGI application. Run it with Nexa's
built-in server for local development. For production, install the app and
Nexa.py in the host's supported Python environment, set `HOST=0.0.0.0` and a
platform-provided `PORT`, configure the secrets above, and use a Python WSGI
server such as Waitress to serve `app:app` behind HTTPS. Configure the reverse
proxy's request-size limit to allow at least the 24 MiB archive limit plus
multipart overhead. Do not assume a JavaScript-only hosting platform supports
the Nexa.py runtime.

## Package archive contract

NovaNX accepts a `.tar.nx` tar archive containing one `nexa.toml` manifest at
the archive root or one level below it. A UTF-8 `README.md` may accompany the
manifest. For example:

```toml
[package]
name = "nexaextra"
version = "1.2.0"
description = "Helpful Nexa utilities"
license = "MIT"
requires_nexa = ">=0.5.2"
python_requires = ">=3.11"
repository_url = "https://github.com/example/nexaextra"

[dependencies]
httpx = ">=0.27"
```

Dependencies can also be a TOML array of strings. Uploads are size-limited,
checked for traversal, duplicate file paths, links, special files, excessive
entry counts, and oversized expanded content. NovaNX reads the manifest and
README without extracting the archive, computes SHA-256, and never executes
uploaded contents. A release name and semantic version come from its manifest;
published versions cannot be overwritten.

## Routes and Nova metadata

- `/` — registry homepage
- `/search` — search and sort packages
- `/package/<name>` — package details, releases, compatibility, README, and install command
- `/docs` — registry and publishing guide
- `/dashboard` — authenticated package and maintainer management
- `/api/packages/search?q=...` — JSON package search
- `/api/packages/<name>` — package information
- `/api/packages/<name>/versions` — release list
- `/api/packages/<name>/download?version=<version>` — archive download (also accepts POST)
- `/api/packages/publish` — authenticated `.tar.nx` upload
- `/api/packages/<name>/versions` — authenticated version upload
- `/<name>/<version>` — version metadata

The inspected Nexa.py `NXserver` configures static/template directories but does
not automatically expose a static route. NovaNX serves its CSS through a
path-confined Nexa route at `/static/<asset>`.

The Nova package manager source was not present in the provided workspace or
the linked Nexa.py framework repository. Therefore the metadata route is
explicitly **provisional**, not verified against Nova's implementation. Its
JSON includes `name`, `version`, `latest_version`, `checksum`, and both
`download_url` and `download_link` (the same absolute URL when
`PUBLIC_BASE_URL` is configured, otherwise a registry-relative URL), plus
package compatibility, dependency, license, author, and release fields.
Confirm the exact Nova field names against Nova's repository before advertising
this endpoint as fully compatible.

## Security notes

- Privileged database and storage operations run only on the backend.
- Supabase RLS policies are included; the service role is used only after
  NexaNX verifies the signed-in user and checks owner/maintainer permissions.
- Browser sessions use signed, HttpOnly, SameSite cookies and POST forms use a
  CSRF token. Enable secure cookies over HTTPS.
- All user-controlled text is HTML-escaped in NXscript templates. Content
  security headers disable scripts and third-party resources.
- NovaNX does not extract or execute uploaded archives.
