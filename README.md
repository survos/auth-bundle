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
