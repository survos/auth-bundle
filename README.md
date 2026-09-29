# Survos Auth Bundle

Symfony bundle for OAuth login and provider-driven onboarding UX.

```bash
composer req survos/auth-bundle
```

## Configuration Model

Use `survos_auth` as the canonical config. The bundle prepends `knpu_oauth2_client` client config automatically.

### 1) Configure providers

`config/packages/survos_auth.yaml`:

```yaml
survos_auth:
    production_url_base: '%env(PRODUCTION_URL)%'
    providers:
        github:
            client_id: '%env(OAUTH_GITHUB_CLIENT_ID)%'
            client_secret: '%env(OAUTH_GITHUB_CLIENT_SECRET)%'
            scopes: ['user:email', 'read:user']
        google:
            client_id: '%env(OAUTH_GOOGLE_CLIENT_ID)%'
            client_secret: '%env(OAUTH_GOOGLE_CLIENT_SECRET)%'
            scopes: ['email', 'profile', 'openid']
```

Optional per-provider keys supported:

- `type`
- `redirect_route`
- `redirect_params`
- `use_state`

Global optional key:

- `production_url_base` (used by provider setup pages to render production callback URLs)

`scopes` are used by your app at redirect time and are not forwarded into KnpU config.

### 2) Add env vars

```bash
OAUTH_GITHUB_CLIENT_ID=
OAUTH_GITHUB_CLIENT_SECRET=
OAUTH_GOOGLE_CLIENT_ID=
OAUTH_GOOGLE_CLIENT_SECRET=
```

### 3) Keep knpu config minimal

`config/packages/knpu_oauth2_client.yaml`:

```yaml
knpu_oauth2_client:
    clients: { }
```

## User Entity

Implement `OAuthIdentifiersInterface` and use `OAuthIdentifiersTrait`.

All providers share one nullable `identifiers` JSONB column. Do not add provider-specific
ID properties or traits such as `GoogleIdTrait`. Adding a provider needs configuration,
not another database migration. Password hashes remain separate; OAuth-only users need
a nullable password column.

The public `identifiers` property uses a PHP property hook to normalize legacy string
IDs into records. `setIdentifier('google', '123')` stores `['google' => ['id' => '123']]`;
setting another provider preserves the existing entries. Existing array records remain
readable, and the method accessors remain available for existing callers. New login
records contain the provider ID, not access tokens or a complete provider profile.
Exclude this field from session serialization if legacy records contain tokens.

```php
use Survos\AuthBundle\Traits\OAuthIdentifiersInterface;
use Survos\AuthBundle\Traits\OAuthIdentifiersTrait;

class User implements OAuthIdentifiersInterface
{
    use OAuthIdentifiersTrait;
}
```

## Useful Routes

- `/oauth/connect/{provider}`
- `/oauth/check/{provider}`
- `/oauth/providers`
- `/oauth/provider/{providerKey}`

## UI

Twig components are available and should be rendered with `twig:` tags.

```twig
<twig:OAuth />
<twig:auth_login />
<twig:auth_register />
<twig:auth_profile />
```

## Local accounts and sign-in methods

Social login creates an app-owned user with a nullable password. Returning users are
looked up by provider key and stable subject in `identifiers`, including legacy scalar
and `token` records. Email alone never links accounts. PostgreSQL and SQLite are supported;
other platforms need a corresponding JSON lookup implementation.

A matching email prompts the reader to sign in using their existing method and then
connect the provider from Account settings. `/auth/account` (`auth_profile`) offers
CSRF-protected provider linking and optional password creation. Linking requires an
existing authenticated session and a fresh provider authorization with matching state;
identities already owned by another user cannot be attached. Existing passwords must
be supplied before replacement. Passwords use Symfony's configured hasher.

The local user's ID stays unchanged, so bookmarks, folders, and other app-owned data
remain attached regardless of sign-in method. Museum membership, onboarding and role
approval remain the host application's responsibility. Configure `login_route` (default
`app_login`) and `new_user_redirect_route` for the host app. The callback must be handled
by `Survos\AuthBundle\Security\Authenticator` on the firewall.

Bundle regression tests from the monorepo:

```bash
vendor/bin/phpunit --no-configuration --bootstrap bu/auth-bundle/tests/bootstrap.php bu/auth-bundle/tests
```

## Setup skill

Use [oauth-login](skills/oauth-login/SKILL.md) when wiring another application:
provider callbacks, app-owned accounts, optional passwords, linking, credentials,
schema rollout, and verification. It includes Ink's working configuration as a
reference without embedding credentials.
