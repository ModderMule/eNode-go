# Meta API: downloading torrent and Usenet results, with optional accounts

eNode-go merges torrent and Usenet releases into eD2K search results
(see [meta-search.md](meta-search.md)). A row carries a meta hash and `FT_META_*`
tags, but not the `.torrent` or `.nzb` itself. The **Meta API** serves those files to
a client such as eMuleQt. It is phase 4 of `docs/meta-search-torrent-usenet-plan.local.md`.

The operator can require an **account** to use the API. Accounts are off by default,
so the API is public. With them on, a user registers on the server's own website
first. Registration can include steps such as payment. The API tells the client
whether an account is required, whether the user is logged in, and which link to
open to register or finish registering.

Everything is off by default (`metaApi.enabled: false`).

## Wiring

```
eMuleQt ──eD2K search──► eNode-go ──► row: meta hash + FT_META_ID (catalog_id)
   │                         ▲
   │   OP_SERVERIDENT: ST_META_API (0x9E) = gRPC base URL, ST_META_API_VER (0x9F) = 1
   │                         │
   ├──gRPC (h2c or TLS)──► :4671  MetaApi / AccountApi          (on with the API)
   └──HTTP (optional)────► :4672  Connect protocol, /caps, /meta/v1/{hash}, /account website
                                  │
                                  └─ MetaIngest.FetchMetaFile ──► torrent-crawler / usenet-crawler
```

The contract is `enodemeta/proto/enode/meta/v1/api.proto`, in the shared submodule.
eMuleQt generates its C++ code from the same file. Its two services reuse `MetaFile`,
`MetaKind` and the `Search*` messages from `meta.proto`:

| RPC | Auth | Purpose |
|---|---|---|
| `MetaApi.GetCaps` | never | Contract version, kinds served, auth mode, registration and account URLs, HTTP endpoint URL. |
| `MetaApi.GetMetaFile` | when accounts are on | The `.torrent` / `.nzb` behind a row, verified against the meta hash. |
| `MetaApi.Search` | — | Reserved for phase 7. It answers `unimplemented`, and `Caps.search_available` is false. |
| `AccountApi.GetAuthStatus` | optional | Login state, account state, expiry, open registration steps, links. It never fails for a missing or bad credential. |
| `AccountApi.Login` | — | Takes a username and password and returns a bearer token. |
| `AccountApi.Logout` | bearer | Revokes the token. |

## Transports

Both listeners are served by connect-go v2 (`metaapi/server.go`). No grpc-go is
involved.

- **gRPC listener** (`metaApi.grpc`, default `0.0.0.0:4671`). It speaks gRPC and
  gRPC-Web only. Any other content type gets `415`, so it never doubles as the plain
  HTTP endpoint. Without TLS it serves gRPC over h2c.
- **HTTP listener** (`metaApi.http`, default `0.0.0.0:4672`, **off**). It serves:
  - the same services over the Connect protocol, for example
    `POST /enode.meta.v1.MetaApi/GetMetaFile` with a proto or JSON body;
  - `GET /caps`, which is `GetCaps` as JSON;
  - `GET /meta/v1/{meta hash hex}?id={catalog_id}`, which returns the raw bytes with
    `Content-Type: application/x-bittorrent` or `application/x-nzb`.

  When accounts are on, this listener also serves the account website under
  `/account`, even with `http.enabled: false`. In that case it serves only the
  website, not the API.

`tls.certFile` / `tls.keyFile` serve both listeners over TLS. With
`tls.advertiseFingerprint`, the SPKI pin of the certificate
(`sha256/<base64>`) is sent as `ST_META_API_FP` (0x9C), so a client can trust a
self-signed certificate on a bare-IP server.

`ST_META_API` carries the gRPC base URL, or the HTTP one when gRPC is off. An empty
`advertiseURL` derives it from the advertised server IP and the listener port.
The tags are sent only when the API is on, so the `OP_SERVERIDENT` every other
server sends is byte-for-byte unchanged.

## Fetching a metafile

`GetMetaFile(meta_hash, catalog_id)`: the client echoes the row's `FT_META_ID` as
`catalog_id`, because the hash fold cannot be reversed. The steps are:

1. The kind is read from the hash: BT v1 and BT v2 go to the torrent network, NZB
   to the usenet network. A network that is not enabled answers `not_found`.
2. A verified copy is served from a byte-bounded LRU cache
   (`metafileCache.maxBytes`, default 256 MiB, `ttlSeconds`). The cache is keyed by
   hash alone, which is safe because every entry was verified against that hash.
3. Otherwise the server calls `MetaIngest.FetchMetaFile(catalog_id)` on the owning
   daemon, bounded by `fetchTimeoutMs`. Concurrent requests for the same release
   share one daemon call.
4. `enodemeta.VerifyMetaFile(hash, bytes)` checks the bytes. If the file does not
   fold to the hash, the answer is `data_loss` and nothing is cached.
5. "Not found" and "failed verification" are remembered for `negativeTtlSeconds`.

Nothing has to be stored per row: the client supplies `catalog_id`, and the check
in step 4 makes a wrong one harmless. A client must still run the same check
itself (plan §8.4), because the row and the bytes arrive over different transports.

Errors carry an `enode.meta.v1.ErrorInfo` detail with a `msg_code`:

| Code | `msg_code` |
|---|---|
| `invalid_argument` | `metafile.invalid_request`: not a meta hash, or no `catalog_id` |
| `not_found` | `metafile.not_found` |
| `data_loss` | `metafile.verify_failed` |
| `unavailable` | `metafile.upstream_unavailable` |
| `resource_exhausted` | `metafile.too_large` or `ratelimit.exceeded` |
| `unauthenticated` | `auth.required`, `auth.invalid_credentials`, `auth.session_expired` |
| `permission_denied` | `account.pending`, `account.expired`, `account.disabled`, with `pending_steps` |

The texts are in `locales/{en,de}.json`. The raw HTTP route returns the same
information as JSON: `{"code", "message", "info": ErrorInfo}`, with the matching
HTTP status, and `WWW-Authenticate: Basic` on a `401`.

Rate limits: `rateLimit.perIPPerMinute` for every download, and
`perAccountPerMinute` per account when accounts are on. Behind a reverse proxy, set
`trustForwardedFor` so the limits see real client addresses.

## Accounts

`metaApi.accounts.enabled: true` makes `GetMetaFile` and `Search` require an
**active** account. Other conditions for turning accounts on:

- Accounts require `tls`, or `allowInsecureAuth: true` when a TLS proxy terminates
  in front of both listeners.
- `publicURL` is the website as users reach it. Registration links are built from
  it.

### How a client authenticates

- **Bearer:** call `Login(username, password, client)` once and send
  `Authorization: Bearer <token>` afterwards. The token lasts `sessionTtlHours`
  (default 30 days). Only its SHA-256 is stored.
- **Basic:** `Authorization: Basic base64(user:pass)` on any call. This is meant for
  the raw HTTP route and scripts. A verified credential is cached for 5 minutes, so
  sending Basic on every download does not pay for an argon2id hash each time.

Passwords are hashed with argon2id (19 MiB, 2 passes). An unknown username takes as
long to reject as a wrong password.

### Recommended eMuleQt flow

```
GetCaps ─► auth_mode == PUBLIC ─────────────────────────────► GetMetaFile
        └► ACCOUNT_REQUIRED ─► have a token? ─ yes ─► GetAuthStatus
                                  │ no                  ├ ACTIVE ─► GetMetaFile
                                  ▼                     └ PENDING / EXPIRED ─► show pending_steps[].url
                   show "Register" (registration_url)
                   and a login form ─► Login ─► store token
```

`GetAuthStatus` and the `permission_denied` detail both list `pending_steps`. Each
step has an `id`, a `kind` (payment, email verification, approval, other), a
`title` in the caller's `Accept-Language`, a `url` to open in the browser, and a
`msg_code`. A client needs no knowledge of any particular step. It only opens the
URL.

### Account states

| State | Meaning |
|---|---|
| `PENDING` | Registered, but a configured step is still open. |
| `ACTIVE` | Every step is done and access has not expired. |
| `EXPIRED` | A paid period ended. Renewable steps are open again. |
| `DISABLED` | Disabled by the operator. |

Access time (`AccessUntil`) is granted by steps. Several grants add up, each counted
from the later of now and the current end. A grant of 0 days means no expiry.

### The website

The website (`accounts/portal.go`) lives under `/account` and uses plain
server-rendered HTML with no JavaScript. Its pages:

- `/account/register`
- `/account/login`
- `/account`: state, access end, open steps, and a renewal link
- `/account/step/{id}/…`: each step's own pages

Security measures:

- Cookie sessions are `HttpOnly`, `SameSite=Lax`, and `Secure` when `publicURL` is
  https.
- Forms carry a double-submit CSRF token.
- Register and login are rate-limited per IP.
- Pages send a strict CSP and `Cache-Control: no-store`.
- Only known MsgCodes are shown as notices, so no text can be injected through the
  URL.

Pages are in English or German, chosen by `Accept-Language`.

## Registration steps

Registration is an ordered list of pluggable steps (`metaApi.accounts.steps`). No
enabled step means a new account is active immediately. Each entry has an `id`
(used in URLs), a `type`, `enabled`, and whatever keys that type defines. The
config layer keeps those keys as a raw YAML node for the step to decode, so a new
step type needs no config change.

A step type implements `accounts.Step` and is registered by name in
`cmd/enode/metaapi.go` (`accountStepRegistry`). The core, the schema and the
contract stay the same. A step:

- checks itself (`Check`), and calls `Host.CompleteStep` or `Host.GrantAccess`
  when it completes;
- mounts its own pages under `/account/step/{id}/`;
- keeps its state in `account_steps.data` or in its own rows;
- may implement `Poller` for background reconciliation.

`Durable()` steps, which include every step that takes money, refuse to start on
the memory engine. `Renewable()` steps reopen when access expires.

Built in:

| `type` | Package | What it does |
|---|---|---|
| `payment` | `accounts/payment` | Plans × payment providers. |

Candidates for later, which need no changes to the above: `email_verification`,
`admin_approval`, `invite_code`, and more payment providers.

### The payment step

```yaml
- id: payment
  type: payment
  enabled: true
  renewable: true
  refundWindowDays: 0                 # >0: take access back on refund/cancel within N days
  title: {en: "Membership", de: "Mitgliedschaft"}   # optional
  plans:
    - id: monthly
      title: "30 days"
      periodDays: 30                  # 0 = never expires
      providerRefs: {woocommerce: "123"}
  providers:
    woocommerce: {enabled: true, storeURL: …, consumerKey: …, consumerSecret: …, webhookSecret: …}
```

The flow:

1. The user picks a plan (and a provider, when more than one sells it).
2. The server stores a `payments` row.
3. The provider opens an order.
4. The user is redirected to the provider's payment page.

The payment is confirmed through whichever path sees it first:

- the return URL;
- a webhook;
- the user's next status request (throttled to one provider lookup per payment
  every 10 s);
- the background poller, every `pollSeconds`.

All four go through the same `reconcile`. It asks the provider (`Fetch`) and never
trusts a callback on its own. Once the payment is paid, it grants the plan exactly
once, guarded by `MarkPaymentCredited`, which is a compare-and-set on
`payments.credited_at`.

Other rules:

- A renewal is a new payment.
- Open payments older than 30 days are marked cancelled and no longer polled.
- **Refunds and cancellations** (`refundWindowDays`, default `0` = off): for that many
  days after crediting, a payment keeps being re-checked, hourly by the poller and at
  once when a webhook names it. If the provider now reports it refunded, cancelled or
  failed, the payment is marked revoked exactly once (`MarkPaymentRevoked`, a
  compare-and-set on `payments.revoked_at`) and its days are taken back: the access end
  moves back by the plan's period (a no-expiry plan ends access now). Other stacked
  purchases keep their time; once access has run out, the payment step reopens with
  `step.payment.refunded`. WooCommerce partial refunds leave the order `completed` and
  are not acted on.

A provider implements `payment.Provider` (`Checkout`, `Fetch`, `Webhook`) and is
registered by name. The schema is provider-neutral: `payments.provider`,
`external_id` and `external_key`.

### WooCommerce

`accounts/payment/woocommerce` uses the shop's REST API (`/wp-json/wc/v3`).

- **Checkout:** `POST /orders` with `status: pending`, the plan's product as the
  only line item, and meta `_enode_account_id`, `_enode_payment_id` and
  `_enode_return_url`. The user is sent to the order's `payment_url`, the shop's
  own "pay for order" page, so any payment gateway the shop has installed works.
- **Status:** `GET /orders/{id}`. `processing` and `completed` count as paid;
  `failed`, `cancelled`/`trash` and `refunded` map to their own states; everything
  else is pending. An order whose `_enode_payment_id` names another payment is
  refused.
- **Auth:**
  - An https shop uses HTTP Basic with the consumer key and secret.
  - A plain-http shop uses one-legged OAuth 1.0a (HMAC-SHA256), because WooCommerce
    refuses Basic over HTTP. Plain HTTP is allowed only on loopback, or with
    `allowInsecureStore`.
  - A shop without pretty permalinks is reached through `?rest_route=`, which is
    detected automatically.

Shop setup:

1. Under WooCommerce → Settings → Advanced → REST API, create a key with
   **Read/Write** permission. Put it in `enode.local.yaml`, never in a tracked file.
2. Create one **virtual** product per plan. It can be private. Put its id in
   `providerRefs.woocommerce`.
3. Optionally, under Settings → Advanced → Webhooks, add a webhook with topic
   *Order updated*, delivery URL `{publicURL}/account/step/payment/hook/woocommerce`,
   and a secret. Put the secret in `webhookSecret`. Without a webhook, the poller and
   the user's own status requests still confirm every payment.
4. Optionally, send buyers back to the account page after they pay: the order meta
   `_enode_return_url` holds the URL. A snippet in the shop's theme can redirect
   there on the order-received page:

   ```php
   add_action('woocommerce_thankyou', function ($order_id) {
       $url = get_post_meta($order_id, '_enode_return_url', true)
           ?: wc_get_order($order_id)->get_meta('_enode_return_url');
       if ($url) { wp_safe_redirect($url); exit; }   // allow the host via allowed_redirect_hosts
   });
   ```

## Storage

Accounts are stored by the configured storage engine, behind
`storage.AccountStore`. The eD2K `Engine` interface is unchanged.

| Engine | Tables / collections | Notes |
|---|---|---|
| `mysql` (MySQL / MariaDB) | `accounts`, `account_steps`, `payments` (incl. `credited_at` / `revoked_at`), `account_sessions` | The DDL is embedded (`storage/accounts_mysql.sql`) and applied at startup with `CREATE TABLE IF NOT EXISTS`, so existing databases get the tables too. `uint64` keys; `created_at` and `updated_at` last. |
| `mongodb` | The same, plus `account_counters` | `uint64` ids from a counter document; a unique partial index on `(provider, external_id)`; a TTL index on session expiry. |
| `memory` | In process | Lost on restart, which is logged as a warning. Durable (paid) steps refuse to start on it. |

Nothing is created unless accounts are enabled.

## Dashboard

`/stats.json` and the admin page show a **Meta API** section when the API is on:
- the mode and URLs;
- metafiles served and cache hits;
- fetch failures (not found, failed verification, upstream);
- how many requests were rate limited;
- account counts by state;
- logins and failed logins.

With accounts on, the dashboard also manages them at `/accounts`: search, disable and
enable, move the access end by days, skip a registration step, and inspect payments.
From loopback no login is needed; from anywhere else it needs `admin.username` and
`admin.password`. See [admin-status-dashboard.md](admin-status-dashboard.md).

## Testing

- `go test ./accounts/... ./metaapi ./storage ./config ./locales ./ed2k` covers:
  - fetching and verification;
  - real-socket tests of gRPC over h2c, the Connect protocol and the raw route;
  - auth in public and account mode;
  - step ordering, expiry and renewal;
  - exactly-once crediting under concurrent confirmations;
  - the website with CSRF;
  - the WooCommerce client against a fake shop, including an OAuth signature vector
    computed with `openssl`.
- `ENODE_INTEGRATION=1 go test ./storage -run AccountStore` runs the store
  conformance suite on MySQL 8, MariaDB 11 and MongoDB 7 in Docker.
- A live WooCommerce shop test is gated on the environment:
  ```
  ENODE_WOO_TEST_URL=http://localhost/wordpress/ ENODE_WOO_TEST_KEY=ck_… ENODE_WOO_TEST_SECRET=cs_… \
    go test ./accounts/payment/woocommerce -run TestLiveShop -v
  ```
  It creates a private product and an order, completes the order, checks the
  status, and deletes both.
- Manual check with grpcurl (the server has no reflection, so pass the proto):
  ```
  grpcurl -plaintext -import-path enodemeta/proto -proto enode/meta/v1/api.proto \
    127.0.0.1:4671 enode.meta.v1.MetaApi/GetCaps
  ```
