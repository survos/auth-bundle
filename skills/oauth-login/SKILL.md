---
name: oauth-login
description: Wire Google or other social sign-in into a Symfony application using survos/auth-bundle, including provider callbacks, app-owned accounts, explicit account linking, optional passwords, and production rollout. Use when enabling or diagnosing social login in Survos apps such as Ink, news, SSAI, Voxstory, or Fotostory.
---

# Social login with auth-bundle

Reuse the bundle's account flow. The host application's User owns bookmarks and
other records regardless of sign-in method. App-specific onboarding, museum
association, and role approval stay in the host app.

## Inspect before wiring

Read the app's instructions, User entity, security configuration, auth route
imports, Composer lock, and existing provider configuration. Check the installed
bundle version and whether vendor is symlinked to mono: a local success with an
unreleased symlink does not establish that production has the same code.

The shared account/linking implementation starts at auth-bundle 2.34.15. Consult
`src/SurvosAuthBundle.php`, `src/Controller/OAuthController.php`, and
`src/Controller/ProfileController.php` relative to the bundle root for current
configuration and routes. Use `debug:router` to determine the actual callback;
route prefixes can vary by app. Do not guess a callback from a provider name.

## User and schema

- Implement `Survos\AuthBundle\Traits\OAuthIdentifiersInterface` and use
  `OAuthIdentifiersTrait`. All provider identities live in one nullable JSONB
  `identifiers` field, e.g. `{"google":{"id":"provider-subject"}}`.
- Remove obsolete per-provider fields/traits from application code only after
  inspecting whether existing identity data needs conversion. Adding a provider
  must not require a new column or trait such as GoogleIdTrait.
- Password hashes remain in a separate nullable password field. A first social
  login creates a local account without requiring a password. Account settings
  can add one later; changing an existing password requires the current password.
- Session serialization must tolerate null passwords. Exclude identifiers from
  sessions if old records could contain access tokens.
- Inspect existing data and prepare a scoped schema migration by default. Preserve
  account IDs, passwords, bookmarks, and existing provider IDs. If the user chooses
  direct schema synchronization instead, apply only reviewed changes and record
  which environments were updated. Do not claim deployment will run a migration
  that does not exist. Never recreate the user table as an OAuth setup shortcut.

The resolver recognizes canonical `id`, legacy `token`, and legacy scalar IDs;
new records contain the provider subject, not OAuth access tokens. PostgreSQL and
SQLite lookups are implemented. Do not promise support for another database
without checking the resolver.

## Wire the app

Install the provider's league/oauth2 client (Google: `league/oauth2-google`) and
register auth-bundle and KnpU's OAuth bundle. Prefer the bundle's `survos_auth`
provider configuration; preserve equivalent working KnpU configuration instead
of defining the same client twice. Configure the app's user class, login route,
home/new-user redirect route, and production URL base.

Add `Survos\AuthBundle\Security\Authenticator` to the existing firewall's
`custom_authenticators`; keep the app's user provider and form login entry point.
Ensure the callback is covered by that firewall and reachable anonymously.
Retain CSRF protection and OAuth state validation. Link Google from the app's
login UI and expose `auth_profile` for account settings to signed-in users.

Do not implement another callback user-creation path in the app. The shared
resolver looks up the stable provider subject. A matching email alone does not
link accounts: the user signs in with their existing method and explicitly
connects the provider from Account settings. Provider linking is a CSRF-protected
POST tied to the current user and OAuth state. Preserve this behavior.

## Google configuration and credentials

Use Google Auth Platform in the chosen Google Cloud project and an OAuth client
of type **Web application**. An API key, service account, Gemini configuration,
or Agent Platform configuration is not needed for website sign-in.

Production does not inherently require a separate Cloud project. One OAuth
client may list both tunnel and production callbacks; separate clients are useful
for separate credentials. Respect the user's chosen arrangement. Register exact
HTTPS redirect URIs including the route path. Keep still-used tunnel callbacks.
Origins alone do not substitute for Authorized redirect URIs. Review the consent
screen's audience/testing status for the intended users; do not silently publish
or broaden it when only a test setup was requested.

Read a downloaded client JSON without printing `client_secret`. Verify
`web.project_id`, callback URLs, and the intended client before using the latest
file; newest is not sufficient evidence on its own. Store local credentials in
ignored `.env.local` and production credentials in deployment config. Commit only
empty env placeholders. Never put secrets in this skill or in command output.

For an authorized Dokku rollout, verify the app name from its remote/domain, then
set `OAUTH_GOOGLE_CLIENT_ID` and `OAUTH_GOOGLE_CLIENT_SECRET` with
`config:set --no-restart`. Capture/suppress stdout and stderr: Dokku can echo the
values. Verify values internally and report only match/presence. These values
become active on the next deployment/restart; setting them alone is not rollout.
Use the existing deployment workflow or dokku-deploy skill when available.

Ink's reference setup (2026-09-29): project `inkstory-510111`; separate tunnel and
production clients; production callback
`https://inkstory.org/auth/connect/controller/google`; tunnel callback
`https://m4-ink.survos.org/auth/connect/controller/google`; Dokku app `ink`.
These are examples, not defaults for another app.

## Release and verify

If bundle code changed, commit/release mono and verify the package split and
Packagist version before updating the app's Composer lock. Commit the app and push
its source before deploying. Check schema synchronization against the target
mapping; the release's migrations cannot compensate for missing migration files.

Verify the provider page and login button, then inspect the outgoing OAuth
redirect for the intended client, exact callback, scopes, and state without
logging credentials or authorization codes. Test cancellation and safe failure
handling. A successful redirect is not proof of completed Google consent.

Run the shared tests from mono:
`vendor/bin/phpunit --no-configuration --bootstrap bu/auth-bundle/tests/bootstrap.php bu/auth-bundle/tests`.
Use Ink's `tests/oauth-account-smoke.php` as a reference for transactional tests of
new/returning identity resolution, optional-password login, and ownership retained
across sign-in methods. Adapt to each app's data model; do not copy Ink story IDs.
Finish with a human social login and save/restore a bookmark when that requires
the user's Google session. Report that step as pending until actually verified.
