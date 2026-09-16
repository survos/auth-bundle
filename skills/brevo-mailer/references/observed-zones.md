# Brevo record sets on working Survos domains

Read from Cloudflare on 2026-09-16. These are evidence of what works, not values
to copy: the `brevo-code` is per Brevo account and the DKIM key per domain, so
always take current values from the Brevo dashboard. Key material is truncated.

## villagedesk.org — the complete set, apex and a subdomain sender

```
TXT  villagedesk.org                           brevo-code:0b1a7f…
TXT  villagedesk.org                           v=spf1 include:spf.brevo.com include:_spf.mx.cloudflare.net ~all
TXT  mail._domainkey.villagedesk.org           k=rsa;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDeMVIz…
TXT  _dmarc.villagedesk.org                    v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com

TXT  outreach.villagedesk.org                  brevo-code:0b1a7f…
TXT  outreach.villagedesk.org                  v=spf1 include:spf.brevo.com ~all
TXT  mail._domainkey.outreach.villagedesk.org  k=rsa;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDeMVIz…
TXT  _dmarc.outreach.villagedesk.org           v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com
```

What it shows:

- **The subdomain sender repeats the whole set.** `outreach.villagedesk.org` has
  its own verification code, SPF, DKIM and DMARC — the apex records do not
  cover it.
- **Two TXT records at the apex is fine** when only one of them is SPF: the
  `brevo-code` and the `v=spf1` record coexist.
- **SPF merges providers.** Brevo sends, and Cloudflare Email Routing receives,
  so both includes sit in one record.
- **DKIM is a TXT at `mail._domainkey`,** not the `brevo1`/`brevo2` CNAME pair
  newer Brevo accounts are given.

## survos.com — Brevo alongside several other senders

```
TXT  survos.com                 v=spf1 include:_spf.google.com include:spf.brevo.com ~all
TXT  mail._domainkey.survos.com k=rsa;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDeMVIz…
TXT  _dmarc.survos.com          v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com
```

Also present: `google._domainkey`, three Amazon SES DKIM CNAMEs, and legacy
`mailjet`, `mandrill` and `mlsend` selectors.

What it shows:

- **Google and Brevo share one SPF record.** Adding a second `v=spf1` record for
  Brevo would have broken Google Workspace mail as well.
- **Why DMARC stays at `p=none` here:** SES, Google and Brevo all send as
  survos.com. Tightening the policy before every one of them is confirmed
  aligned would reject legitimate mail.
- **The SES DKIM records are CNAMEs and are DNS-only.** Any CNAME-based DKIM,
  Brevo's included, has to stay grey-clouded.
