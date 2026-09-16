---
name: brevo-mailer
description: Wire a Symfony app to send transactional mail through Brevo — registration email verification, password reset — and authenticate the sending domain in Cloudflare DNS (Brevo verification code, SPF, DKIM, DMARC). Use when adding registration or any outbound mail to an app that uses survos/auth-bundle, or when Brevo mail is landing in spam or failing domain verification. Do not use for inbound mail, marketing campaigns, or providers other than Brevo.
---

# Brevo mailer with Cloudflare domain authentication

Registration is not finished until a real verification email arrives, passes
authentication, and its link logs the user in. Mail that sends but lands in
spam is a failed deployment, and the cause is almost always DNS.

Read [references/observed-zones.md](references/observed-zones.md) for the
record sets as they actually exist on working Survos domains.

## Non-negotiable gates

- **Never print the API key.** `dokku config:set` echoes every value it sets, so
  `MAILER_DSN=brevo+api://KEY@default` lands in the tool log verbatim. Suppress
  output (`>/dev/null`) and confirm with `dokku config:keys`, which lists names
  only. Never use `config:show` or `config:get` on it.
- **Record values come from the Brevo dashboard, never from memory.** Brevo has
  used more than one DKIM scheme over time (see below). Senders, Domains &
  Dedicated IPs → Domains → the domain → Authenticate shows the exact records
  for *this* account.
- **One SPF record per name.** Two `v=spf1` TXT records at the same name is a
  permanent SPF error, which fails authentication for every sender. Add
  `include:spf.brevo.com` to the existing record rather than creating a second.
- **Read the zone before changing it.** List existing TXT/CNAME records first and
  diff them against the dashboard. DNS changes require the user's authorization.
- **DNS-only, never proxied.** TXT records cannot be proxied, but a CNAME-based
  DKIM record can — and an orange-clouded CNAME returns Cloudflare's addresses
  instead of Brevo's target, so DKIM silently fails. This is the same trap that
  breaks Let's Encrypt on proxied survos.com subdomains.
- **Not done until a real message passes.** Brevo's dashboard showing
  "authenticated" is necessary, not sufficient. Send a real registration email to
  an external mailbox and read its headers.

## Symfony side

```bash
composer require symfony/brevo-mailer
```

`.env` documents the shape; the value lives in `.env.local` or Dokku config:

```dotenv
###> symfony/brevo-mailer ###
# brevo+api is preferred over brevo+smtp: no SMTP credentials to rotate
# separately, and delivery errors come back as API responses.
MAILER_DSN=null://null
# MAILER_DSN=brevo+api://KEY@default
###< symfony/brevo-mailer ###
```

- **Local development stays on `null://null`** (or a local catcher). Do not send
  real mail from a laptop by default.
- **The From address must be on the authenticated domain.** In the verify-email
  flow that is the `TemplatedEmail` built in `RegistrationController` — a
  maker-generated default such as `mailer@your-domain.com` will fail DMARC.
- Setting it in production, without echoing the key:

  ```bash
  ssh fsn1 config:set <app> MAILER_DSN='brevo+api://KEY@default' >/dev/null
  ssh fsn1 config:keys <app> | grep -x MAILER_DSN
  ```

## The DNS record set

For a sending domain `example.org`:

| purpose | type | name | value |
|---|---|---|---|
| Brevo ownership | TXT | `example.org` | `brevo-code:<code from dashboard>` |
| SPF | TXT | `example.org` | `v=spf1 include:spf.brevo.com ~all` — **merged** with any existing includes |
| DKIM | TXT *or* CNAME | see below | from the dashboard |
| DMARC | TXT | `_dmarc.example.org` | `v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com` |

**DKIM has two shapes, and the dashboard decides which:**

- **TXT at `mail._domainkey`** with value `k=rsa;p=...` — what `survos.com` and
  `villagedesk.org` use today.
- **CNAMEs at `brevo1._domainkey` and `brevo2._domainkey`** pointing into
  Brevo's domainkey host — the scheme on newer accounts. These are the records
  that must be DNS-only.

**A subdomain sender is its own domain.** Sending from
`outreach.example.org` needs its own `brevo-code`, SPF, DKIM and `_dmarc`
records at that subdomain; the apex records do not cover it.

Start DMARC at `p=none`. Tighten to `quarantine` only after the Brevo DMARC
reports show every legitimate sender passing — `survos.com` also sends through
Google, SES and others, and a strict policy would reject any sender that is not
aligned.

## Procedure

1. **Read the current zone.** List TXT and CNAME records for the domain and any
   sending subdomain. Note any existing SPF record and every `_domainkey`.
2. **Get the dashboard values.** Add the domain in Brevo and copy its
   `brevo-code`, DKIM record(s) and recommended DMARC.
3. **Show the user the diff** — records to add, the SPF record to *edit*, anything
   conflicting — and get authorization.
4. **Write the records** as DNS-only. Edit SPF in place.
5. **Verify in DNS** before asking Brevo to check:

   ```bash
   dig +short TXT example.org
   dig +short TXT mail._domainkey.example.org   # or CNAME brevo1._domainkey
   dig +short TXT _dmarc.example.org
   ```

   Exactly one line should start `"v=spf1`.
6. **Authenticate in the Brevo dashboard.** Propagation on Cloudflare is usually
   seconds; if Brevo still reports failure, re-run the `dig` checks rather than
   re-adding records.
7. **Send a real message.** Register a new account against production with an
   external mailbox, open the verification email, and check the headers for
   `spf=pass`, `dkim=pass` with `d=example.org`, and `dmarc=pass`. Then click
   the link and confirm the user is marked verified.

## Symptoms and causes

| symptom | usual cause |
|---|---|
| Brevo: domain not verified | `brevo-code` TXT missing, or on the wrong name (subdomain vs apex) |
| `spf=permerror` | two `v=spf1` records at the same name |
| `spf=softfail` | `include:spf.brevo.com` missing from the one SPF record |
| `dkim=fail` with a CNAME scheme | DKIM CNAME is proxied (orange cloud) |
| `dmarc=fail` while SPF and DKIM pass | From address is not on the authenticated domain |
| mail accepted by Brevo, never arrives | sender not verified, or local `null://null` DSN in production config |
