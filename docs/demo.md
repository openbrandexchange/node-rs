# Demo mode

A public demo portal that people can look around in without an account: the fictional fashion house
MAISON NOOR as a showroom (its own theme, login page and start page) over the spec's catalogue of the same
house, a one-click sign-in as a retailer or as the brand's admin, a public read-only API key, and an
automatic reset. It is the node-rs port of node-ts's demo mode (same rules, same ids, same public key), so
`demo.openbrandexchange.com` can move to node-rs without the admin UI noticing.

Demo mode is **off by default** and switched on with `OBX_DEMO=true`. Never set it on a real portal:
**every reset deletes all data** (catalog, retailers, accounts, files) and puts the fixtures back.

```sh
OBX_DEMO=true OBX_PUBLIC_URL=http://localhost:8080 OBX_DATA_DIR=./data-demo node-rs serve
```

The first visit (or the first minute after start) builds the demo; there is no setup wizard and no setup code.

## What it does

| | |
| --- | --- |
| Sign-in | `POST /admin/api/demo/login` with `{"as": "retailer" \| "brand"}` signs in as the demo retailer (Northwind Stores) or the demo brand admin; the two accounts have no password. With `OBX_DEMO_TURNSTILE_SITE_KEY`/`_SECRET` the request needs a Cloudflare Turnstile token (`turnstile_token`). At most 10 per minute and 30 per 10 minutes per address. |
| Banner | `GET /admin/api/public/branding` carries `x-obx-demo` (reset interval, last and next reset, whether the demo is ready, the Turnstile site key, the two accounts and the public API key); admin-ui 0.2.2+ shows the demo banner and the sign-in buttons. `GET /admin/api/demo` returns the same object. |
| Showroom | The spec's `fixtures/examples/BrandingSettings.full.json` (theme, split login page, start page with hero, tiles, products, story, contact). Its images are fixture product photographs, stored as branding images with the example's ids. |
| Data | The MAISON NOOR fixtures embedded in the binary (`obx-conformance`): brands MAISON NOOR and NOOR ATELIER, 11 articles, 46 variants, 35 images with server renditions; retailers Northwind Stores (the demo retailer, all brands, originals), Harbour & Co (MAISON NOOR only, no originals) and Lumen Concept Store (blocked); one open access request (Fjord Outdoor); 140 example download events over 30 days. No seed archive is needed. |
| API | Public read-only key `obxc_demo-portal-read-only` / `obxs_demo-portal-read-only-public` (scopes `catalog:read media:read media:original`, Northwind Stores). Discovery leaves out `webhooks`, `ingest` and `usage` and has no `ingest_url`; those addresses answer `501` with `x-obx-demo`. |
| Reset | Every `OBX_DEMO_RESET_MINUTES` (default 60) **when something changed**: a successful write of a visitor (anything but signing in and out) marks the demo dirty; a demo nobody touched is not reset, except once a day (so the example statistics stay recent) and after a failed reset. Also on demand with `POST /admin/api/demo/reset` (signed-in visitors, at most once per 10 minutes for everyone). Sessions of the two demo accounts survive a reset; old `/changes` cursors answer `410 cursor_expired`. The fixture images and their renditions are kept between resets, everything else in storage (uploads, downloads, exports, other images) is deleted. |

**Refused** (`403 forbidden` with `"x-obx-demo": true`; the UI says "This is not possible in the demo."):
setup; password reset and change; changing the e-mail address; deleting the own account; invitations (also
opening an invitation link); changes to the two demo accounts and to Northwind Stores; creating, renewing or
deleting API keys and upload keys (brand and retailer side); webhooks; scheduled imports and their tests
(deleting one is allowed); the company details and the brand's name; deleting catalog records (unpublishing
works); approving an access request with an API key (untick API access, or decline).

**Neutralised**: no e-mail is ever sent, whatever `OBX_SMTP_URL` says; request bodies are capped at
`OBX_DEMO_MAX_UPLOAD_BYTES` (default 2 MiB; a body without `Content-Length` is refused); every answer has
`X-Robots-Tag: noindex, nofollow`; nothing is cached publicly (`Cache-Control: public` becomes
`private, max-age=300`); at most 20 branding images.

**Allowed**: everything a visitor needs to try the portal: search, EAN list, product pages, image, zip and
CSV downloads, download jobs; as the brand: editing articles, the CSV/Excel import with the template, access
per retailer (Harbour & Co and new retailers), statistics, declining requests, and the portal's look (theme,
login page, start page, logo, favicon, branding images). Everything goes back at the next reset.

**Abuse limits** per client address and minute: 300 reads, 40 writes, 10 demo sign-ins (in memory, per
process). Behind Caddy set `OBX_TRUST_PROXY=true`, so the limits count the visitor's address, not Caddy's.

## Settings

| Variable | Default | |
| --- | --- | --- |
| `OBX_DEMO` | `false` | Demo mode on. |
| `OBX_DEMO_RESET_MINUTES` | `60` | Reset interval (5 to 10080). |
| `OBX_DEMO_MAX_UPLOAD_BYTES` | `2097152` | Largest request body (64 KiB to 32 MiB). |
| `OBX_DEMO_TURNSTILE_SITE_KEY` | | Turnstile widget site key (public). |
| `OBX_DEMO_TURNSTILE_SECRET` | | Its secret key; without it no Turnstile check. |

## Running demo.openbrandexchange.com on node-rs

1. A small server (1 vCPU, 1 GB RAM is plenty) with node-rs installed as in [hosting.md](hosting.md), its own
   data folder, and Caddy in front:

   ```caddy
   demo.openbrandexchange.com {
   	encode zstd gzip
   	reverse_proxy 127.0.0.1:8080
   }
   ```

2. The service environment (systemd `Environment=` or the compose file):

   ```sh
   OBX_DEMO=true
   OBX_PUBLIC_URL=https://demo.openbrandexchange.com
   OBX_TRUST_PROXY=true
   OBX_DEMO_TURNSTILE_SITE_KEY=…   # optional, from the Cloudflare dashboard
   OBX_DEMO_TURNSTILE_SECRET=…
   ```

   Local blob storage is fine; the demo never grows beyond the fixtures and a few uploads.
3. Start it, open the address and check the banner, both sign-in buttons, the public key
   (`curl -u obxc_demo-portal-read-only:obxs_demo-portal-read-only-public -d grant_type=client_credentials https://demo.openbrandexchange.com/obx/v1/oauth/token`)
   and a refused action (creating an API key answers `403` with `x-obx-demo`).
4. Point the DNS record of `demo.openbrandexchange.com` at the new server: in the Cloudflare account that holds
   the zone `openbrandexchange.com`, DNS → Records → Add record, type `A` (and `AAAA` for IPv6), name `demo`,
   the server's address, proxy status **DNS only** (grey cloud), so Caddy obtains its own certificate on the
   first request. A proxied record works too once the zone's SSL/TLS mode is Full (strict), then switch off the node-ts deployment. The public key, the account ids and the refusal
   rules are the same, so links and scripts that use the demo keep working. Sessions do not move: visitors
   sign in again with one click.

Backups are pointless for a demo: every reset rebuilds it from the binary.
