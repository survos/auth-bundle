<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Menu;

use Survos\AuthBundle\Service\AuthService;
use Survos\TablerBundle\Event\MenuEvent;
use Survos\TablerBundle\Menu\MenuBuilderTrait;
use Survos\TablerBundle\Service\IconService;
use Survos\TablerBundle\Service\RouteAliasService;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Routing\RouterInterface;

/**
 * Adds the auth-bundle routes (configured OAuth providers, login, register,
 * profile) to the admin navbar.
 *
 * SurvosTabler is an OPTIONAL dependency of this bundle, so this subscriber is
 * only registered when tabler's MenuEvent is present (see SurvosAuthBundle::
 * loadExtension). Each link self-removes when its route is absent, so the
 * submenu only shows what the app actually exposes.
 */
final class AuthMenuSubscriber
{
    use MenuBuilderTrait;

    public function __construct(
        protected readonly ?RouterInterface   $router            = null,
        protected readonly ?RouteAliasService $routeAliasService = null,
        protected readonly ?IconService       $iconService       = null,
        protected readonly ?AuthService       $authService       = null,
    ) {}

    #[AsEventListener(event: MenuEvent::ADMIN_NAVBAR_MENU)]
    public function onAdminNavbarMenu(MenuEvent $event): void
    {
        $submenu = $this->addSubmenu($event->getMenu(), 'Auth', icon: 'auth');

        // Configured OAuth clients first — they're high priority, so surface each
        // one directly instead of making the user hunt through the providers list.
        // The icon is the provider key, which resolves to a branded alias
        // (github -> tabler:brand-github, google -> tabler:brand-google, ...).
        foreach ($this->authService?->getOauthClientKeys() ?? [] as $clientKey) {
            $this->add(
                $submenu,
                'oauth_provider',
                ['providerKey' => $clientKey],
                label: ucfirst((string) $clientKey),
                icon: $clientKey,
            );
        }

        $this->add($submenu, 'oauth_providers', label: 'All Providers', icon: 'settings', dividerBefore: true);
        $this->add($submenu, 'oauth_profile', label: 'Profile', icon: 'profile');
        $this->add($submenu, 'auth_login', label: 'Login', icon: 'login');
        $this->add($submenu, 'auth_register', label: 'Register', icon: 'add_user');
    }
}
