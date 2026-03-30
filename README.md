# AuthBundle

Symfony Bundle that provides some utilities when working with Symfony authentication.

```bash
composer req survos/auth-bundle
```

## Adding Social Login (OAuth2)

### 1. Configure the OAuth clients

Create `config/packages/knpu_oauth2_client.yaml`:

```yaml
knpu_oauth2_client:
    clients:
        github:
            type: github
            client_id: '%env(OAUTH_GITHUB_CLIENT_ID)%'
            client_secret: '%env(OAUTH_GITHUB_CLIENT_SECRET)%'
            redirect_route: auth_oauth_check
            redirect_params: { service: github }
        google:
            type: google
            client_id: '%env(OAUTH_GOOGLE_CLIENT_ID)%'
            client_secret: '%env(OAUTH_GOOGLE_CLIENT_SECRET)%'
            redirect_route: auth_oauth_check
            redirect_params: { service: google }
```

Add credentials to `.env.local`:

```bash
OAUTH_GITHUB_CLIENT_ID=your_client_id
OAUTH_GITHUB_CLIENT_SECRET=your_client_secret
OAUTH_GOOGLE_CLIENT_ID=your_client_id.apps.googleusercontent.com
OAUTH_GOOGLE_CLIENT_SECRET=your_client_secret
```

### 2. Update your User entity

Implement `OAuthIdentifiersInterface` and use `OAuthIdentifiersTrait`:

```php
<?php

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;
use Survos\AuthBundle\Traits\OAuthIdentifiersInterface;
use Survos\AuthBundle\Traits\OAuthIdentifiersTrait;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity(repositoryClass: UserRepository::class)]
class User implements UserInterface, OAuthIdentifiersInterface
{
    use OAuthIdentifiersTrait;
    
    // ... other properties and methods
}
```

### 3. Run migration

```bash
bin/console make:migration
bin/console doctrine:migrations:migrate
```

### 4. Add login links

```twig
<a href="{{ path('oauth_connect_start', {clientKey: 'github'}) }}">Login with GitHub</a>
<a href="{{ path('oauth_connect_start', {clientKey: 'google'}) }}">Login with Google</a>
```

### 5. Configure callback URLs

Add redirect URIs in your OAuth provider's console:
- GitHub: `https://yourdomain.com/oauth/check/github`
- Google: `https://yourdomain.com/oauth/check/google`

wget -O - https://raw.githubusercontent.com/<username>/<project>/<branch>/<path>/<file> | bash

```bash
ciine rec auth-demo.cast 
symfony new auth-demo --webapp --version=next && cd auth-demo
echo "DATABASE_URL=sqlite:///%kernel.project_dir%/var/data.db" > .env.local

# this is just Symfony
composer config extra.symfony.allow-contrib true
composer require symfonycasts/verify-email-bundle
sed -i "s|# MAILER_DSN|MAILER_DSN|" .env
bin/console make:user --is-entity --identity-property-name=email --with-password User -n
echo ",,," | sed "s/,/\n/g"  | bin/console make:security:form-login

bin/console make:controller AppController
sed -i "s|/app|/|" src/Controller/AppController.php 

echo ",,no,admin@test.com,AuthDemoBot,yes,app_homepage,no" | sed "s/,/\n/g"  | bin/console make:registration-form
bin/console doctrine:schema:update --force
symfony server:start -d

echo "import '@picocss/pico';\n" >> assets/app.js
echo "import '@picocss/pico/css/pico.min.css';\n" >> assets/app.js


cat > templates/app/index.html.twig <<END
{% extends 'base.html.twig' %}
{% block body %}
    <div>
        <a href="{{ path('app_app') }}">Home</a>
    </div>

    {% if is_granted('IS_AUTHENTICATED_FULLY') %}
        <a class="btn btn-primary" href="{{ path('app_logout') }}">Logout {{ app.user.email }} </a>
    {% else %}
        <a class="btn btn-primary" href="{{ path('app_register') }}">Register</a>
        <a class="btn btn-secondary" href="{{ path('app_login') }}">Login</a>
    {% endif %}
{% endblock %}
END
symfony open:local

# add survos/auth-bundle to create users from the CLI
composer config allow-plugins.endroid/installer true
composer req survos/auth-bundle
bin/console survos:user:create admin@test.com password --roles ROLE_ADMIN
bin/console survos:user:create bob@test.com password
bin/console survos:user:create carol@test.com password
symfony server:start -d
symfony open:local --path=/login


```

## Deprecated

```bash
sed  -i "s|some_route|app_app|" src/Security/AppAuthenticator.php
sed  -i "s|// return new|return new|" src/Security/AppAuthenticator.php
sed  -i "s|throw new|//throw new|" src/Security/AppAuthenticator.php
```

