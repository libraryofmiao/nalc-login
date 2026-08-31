# Private Koha + Cloudflare Tunnel setup

This repository is designed so Koha can remain inside the library network. Do not expose `92.4.70.3:8080` directly to the Internet.

## Architecture

```text
Browser
  |
  v
Cloudflare Pages / NALC login
  |
  | server-side request
  v
Cloudflare Tunnel hostname
  |
  | encrypted outbound tunnel
  v
cloudflared on Koha/library network
  |
  v
http://92.4.70.3:8080
```

## 1. Create the tunnel

In Cloudflare Zero Trust, create a tunnel and install `cloudflared` on a machine that can reach the Koha server.

The tunnel's public hostname should point to the local Koha service, for example:

```yaml
ingress:
  - hostname: koha-tunnel.example.org
    service: http://92.4.70.3:8080
  - service: http_status:404
```

Use your real domain/hostname. Do not commit the tunnel token or any credentials to this repository.

## 2. Recommended protection

Protect the tunnel hostname with Cloudflare Access and create a **Service Auth** policy for the NALC Pages Function. Create a service token and keep its two values as Cloudflare Pages secrets.

The Pages Function supports these optional variables:

- `KOHA_ACCESS_CLIENT_ID`
- `KOHA_ACCESS_CLIENT_SECRET`

They are sent only from the Pages Function to the protected tunnel hostname and are never returned to the browser.

## 3. Cloudflare Pages environment variables

Configure these in the Pages project under **Settings → Environment variables** for Production:

| Variable | Value |
|---|---|
| `SECRET_PIN` | Your 6-digit NALC administrative PIN |
| `KOHA_USER` | Your Koha staff username |
| `KOHA_PASS` | Your Koha staff password |
| `KOHA_BASE_URL` | `https://koha-tunnel.example.org` |
| `KOHA_ACCESS_CLIENT_ID` | Access service-token Client ID (if Access is enabled) |
| `KOHA_ACCESS_CLIENT_SECRET` | Access service-token Client Secret (if Access is enabled) |

Never put `KOHA_USER` or `KOHA_PASS` in `index.html`, JavaScript delivered to the browser, GitHub, or the tunnel configuration.

## 4. What happens during login

1. The user enters only the six-digit NALC PIN.
2. `/api/login` validates the PIN.
3. The Pages Function reads `KOHA_USER` and `KOHA_PASS` from its private environment.
4. The Function reaches the private Koha server through the Cloudflare Tunnel.
5. The Function submits the Koha login form server-side.
6. Koha returns its authenticated session cookie.
7. The Function returns only that session cookie to the browser.
8. The browser is sent to `/koha/cgi-bin/koha/mainpage.pl`.
9. Subsequent Koha requests go through the `/koha/*` Pages proxy and then through the tunnel to the private Koha server.

## 5. Important network requirement

The computer running `cloudflared` must be able to reach:

```text
http://92.4.70.3:8080
```

from inside the library network.

The tunnel is outbound, so you do not need to open inbound port 8080 on the library router just for Cloudflare Tunnel.

## 6. Current repository code

`functions/api/login.js` uses `KOHA_BASE_URL` and performs the credentialed Koha login server-side.

`functions/koha/[[path]].js` proxies the authenticated Koha session through the Pages site and also uses `KOHA_BASE_URL`.

The code intentionally does not contain the actual Koha username, password, PIN, or tunnel token.
