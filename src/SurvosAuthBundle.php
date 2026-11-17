<?php

declare(strict_types=1);

namespace Survos\AuthBundle;

use Survos\AuthBundle\Command\UserCreateCommand;
use Survos\AuthBundle\Controller\LoginController;
use Survos\AuthBundle\Controller\OAuthController;
use Survos\AuthBundle\Controller\ProfileController;
use Survos\AuthBundle\Controller\RegisterController;
use Survos\AuthBundle\Security\Authenticator;
use Survos\AuthBundle\Security\DevAutoLoginAuthenticator;
use Survos\AuthBundle\Service\AuthService;
use Survos\AuthBundle\Twig\Components\OAuth;
use Survos\AuthBundle\Twig\TwigExtension;
use Survos\Kit\AbstractSurvosBundle;
use Survos\Kit\Traits\HasConfigurableRoutes;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;

// Symfony\Component\HttpKernel\Bundle\Bundle <-- Flex auto-registration marker (see Survos\Kit\AbstractSurvosBundle)
class SurvosAuthBundle extends AbstractSurvosBundle
{
    use HasConfigurableRoutes;

    protected string $extensionAlias = 'survos_auth';

    public function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $this->addRouteLoaderCompilerPass($container);
    }

    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        // MUST come first: AbstractSurvosBundle::loadExtension() is what scans src/Command/,
        // src/Controller/ and friends and registers them autowired+autoconfigured. Overriding
        // this method without chaining silently skips that scan — the bundle boots, its
        // explicitly-registered services work, and #[AsCommand] classes simply never exist.
        // That is why survos:user:create was missing from bin/console while the bundle was
        // otherwise healthy. build() already chained; this one did not.
        parent::loadExtension($config, $container, $builder);

        $this->captureRouteConfig($config);
        $this->registerRouteLoader($builder);

        $builder->setParameter('survos_auth.providers', $config['providers'] ?? []);
        $builder->setParameter('survos_auth.production_url_base', $config['production_url_base'] ?? null);

        // Dev auto-login. Always registered, because security.yaml names it in a when@dev firewall
        // and a named service that is missing fails the whole container: gating its EXISTENCE on
        // debug made every `APP_ENV=dev --no-debug` CLI run uncompilable, though no command ever
        // authenticates (harvest, 2026-10-11). Whether it acts is decided by $enabled instead: only
        // when a user is configured AND the kernel is in debug. Otherwise supports() is always
        // false, so prod, or an empty DEV_AUTO_LOGIN_USER, gets an authenticator that never matches.
        $devAutoLogin = trim((string) ($config['dev_auto_login'] ?? ''));
        $builder->autowire(DevAutoLoginAuthenticator::class)
            ->setArgument('$userIdentifier', $devAutoLogin)
            ->setArgument('$logger', new Reference('logger', ContainerInterface::NULL_ON_INVALID_REFERENCE))
            ->setArgument('$enabled', '' !== $devAutoLogin && $builder->getParameter('kernel.debug'))
            ->setPublic(false);

        $serviceId = 'survos_auth.base_service';
        $container->services()->alias(AuthService::class, $serviceId);
        $builder->autowire($serviceId, AuthService::class)
            ->setArgument('$userClass', $config['user_class'])
            ->setArgument('$clientRegistry', new Reference('knpu.oauth2.registry'))
            ->setArgument('$logger', new Reference('logger', ContainerInterface::NULL_ON_INVALID_REFERENCE))
            ->setArgument('$config', $config)
//            ->setArgument('$entityManager', new Reference('doctrine.orm.entity_manager'))
//            ->setArgument('$registry', new Reference('doctrine'))
//            ->setArgument('$provider', new Reference('security.user_providers'))
            ->setPublic(true)
        ;

        if ([] !== $config['resources']) {
            $builder->register(Security\ResourceUserProvider::class);
        }

        // the social media login buttons
        foreach ([
            OAuth::class,
            Twig\Components\Login::class,
            Twig\Components\Register::class,
            Twig\Components\Profile::class,
        ] as $componentClass) {
            $builder->register($componentClass)
                ->setAutowired(true)
                ->setAutoconfigured(true);
        }

        $builder->autowire(Service\OAuthUserResolver::class)
            ->setArgument('$userClass', $config['user_class']);
        $builder->autowire(Service\OidcUserResolver::class)
            ->setArgument('$userClass', $config['user_class']);

        $definition = $builder->autowire(Authenticator::class)
            ->setAutowired(true)
            ->setAutoconfigured(true)
            ->setArgument('$clientRegistry', new Reference('knpu.oauth2.registry'))
            ->setArgument('$router', new Reference('router'))
            ->setArgument('$newUserRedirectRoute', $config['new_user_redirect_route'])
            ->setArgument('$loginRoute', $config['login_route'])
        ;

        // SurvosTabler is optional; only wire the admin-navbar menu when it's installed.
        if (trait_exists(\Survos\TablerBundle\Menu\MenuBuilderTrait::class)) {
            $container->services()
                ->set(Menu\AuthMenuSubscriber::class)
                ->arg('$tunnel', new Reference(\Survos\CloudflaredBundle\Service\Tunnel::class, ContainerInterface::NULL_ON_INVALID_REFERENCE))
                ->arg('$productionUrlBase', $config['production_url_base'])
                ->autowire()
                ->autoconfigure();
        }

        $definition = $builder
            ->autowire('survos.auth_twig', TwigExtension::class)
            ->addTag('twig.extension');
        //        $definition->setArgument('$seed', $config['seed']);
        //        $definition->setArgument('$prefix', $config['function_prefix']);

        $builder->autowire(UserCreateCommand::class)
            ->setArgument('$passwordEncoder', new Reference('security.user_password_hasher'))
            ->setArgument('$userProvider', new Reference('security.user_providers'))
            ->setArgument('$eventDispatcher', new Reference('event_dispatcher'))
            ->setArgument('$entityManager', new Reference('doctrine.orm.entity_manager'))
            ->addTag('console.command')
        ;

        // (icons configured via prependExtension)

        $definition = $builder->autowire(OAuthController::class)
            ->setAutowired(true)
            ->setAutoconfigured(true) // avoid setContainer() injection
//            ->setArgument('$authService', new Reference($serviceId))
            ->setArgument('$clientRegistry', new Reference('knpu.oauth2.registry'))
//            ->setArgument('$userAuthenticator', new Reference('security.user_authenticator'))
//            ->setArgument('$logger', new Reference('logger', ContainerInterface::NULL_ON_INVALID_REFERENCE))
            ->setPublic(true);

        foreach ([LoginController::class, RegisterController::class, ProfileController::class] as $controllerClass) {
            $builder->autowire($controllerClass)
                ->setAutowired(true)
                ->setAutoconfigured(true)
                ->setPublic(true)
            ;
        }
    }

    public function configure(DefinitionConfigurator $definition): void
    {
        $children = $definition->rootNode()->children();
        $this->addRouteOptions($children, '/auth');
        $children
            ->arrayNode('authorities')->useAttributeAsKey('name')->arrayPrototype()->children()
                ->stringNode('issuer')->isRequired()->cannotBeEmpty()->end()
            ->end()->end()->end()
            ->arrayNode('resources')->useAttributeAsKey('name')->arrayPrototype()->children()
                ->booleanNode('enabled')->defaultTrue()->end()
                ->stringNode('authority')->isRequired()->cannotBeEmpty()->end()
                ->stringNode('path')->isRequired()->cannotBeEmpty()->end()
                ->stringNode('resource')->isRequired()->cannotBeEmpty()->end()
                ->arrayNode('audiences')->isRequired()->requiresAtLeastOneElement()->stringPrototype()->cannotBeEmpty()->end()->end()
                ->arrayNode('required_scopes')->isRequired()->requiresAtLeastOneElement()->stringPrototype()->cannotBeEmpty()->end()->end()
            ->end()->end()->end()
            ->arrayNode('providers')
                ->useAttributeAsKey('name')
                ->arrayPrototype()
                    ->children()
                        ->scalarNode('type')->defaultNull()->end()
                        ->scalarNode('client_id')->defaultNull()->end()
                        ->scalarNode('client_secret')->defaultNull()->end()
                        ->arrayNode('scopes')->scalarPrototype()->end()->end()
                        ->scalarNode('redirect_route')->defaultNull()->end()
                        ->arrayNode('redirect_params')->scalarPrototype()->end()->end()
                        ->booleanNode('use_state')->defaultNull()->end()
                    ->end()
                ->end()
            ->end()
            ->scalarNode('login_route')->defaultValue('app_login')->end()
            ->scalarNode('new_user_redirect_route')->defaultValue('oauth_profile')->end()
            ->scalarNode('production_url_base')->defaultNull()->end()
            ->scalarNode('user_provider')->defaultValue(null)->end()
            ->scalarNode('user_class')->defaultValue('App\\Entity\\User')->end()
            ->scalarNode('dev_auto_login')
                ->defaultNull()
                ->info('User identifier (usually an email) to auto-authenticate as. Registers DevAutoLoginAuthenticator, which must then be listed in a when@dev firewall\'s custom_authenticators. Ignored entirely outside debug mode — there is no production code path. Point it at an env var so it can be switched off without editing security.yaml.')
            ->end()
        ->end();
    }

    /** Project opt-in resource configuration onto Symfony's native security implementation. */
    private function prependResourceSecurity(ContainerBuilder $builder): void
    {
        $extension = $this->getContainerExtension();
        $config = (new \Symfony\Component\Config\Definition\Processor())->processConfiguration(
            $extension->getConfiguration([], $builder),
            $builder->getExtensionConfig($this->extensionAlias),
        );
        if ([] === $config['resources']) {
            return;
        }
        $resources = array_filter($config['resources'], static fn (array $resource): bool => $resource['enabled']);
        if ([] === $resources) {
            return;
        }
        if (!class_exists(\Symfony\Component\Security\Http\Authorization\OAuth2ScopeVoter::class)
            || !class_exists(\Jose\Component\Core\AlgorithmManager::class)) {
            throw new \LogicException('survos_auth.resources requires Symfony Security 8.2+ and web-token/jwt-library ^4. Install these before enabling resource authentication.');
        }

        $security = ['providers' => ['survos_resource' => ['id' => Security\ResourceUserProvider::class]], 'firewalls' => [], 'access_control' => []];
        foreach ($resources as $name => $resource) {
            if (!isset($config['authorities'][$resource['authority']])) {
                throw new \InvalidArgumentException(sprintf('Unknown authority "%s" for resource "%s".', $resource['authority'], $name));
            }
            // Trust boundaries and routes are resolved at compile time, never from request headers.
            $issuer = $builder->resolveEnvPlaceholders($config['authorities'][$resource['authority']]['issuer'], true);
            $uri = $builder->resolveEnvPlaceholders($resource['resource'], true);
            foreach ([$issuer, $uri] as $url) {
                $parts = parse_url($url);
                if (false === $parts || 'https' !== ($parts['scheme'] ?? null) || empty($parts['host'])
                    || isset($parts['user']) || isset($parts['query']) || isset($parts['fragment'])) {
                    throw new \InvalidArgumentException('Auth issuer and resource must be absolute HTTPS URLs without credentials, query or fragment.');
                }
            }
            $path = $resource['path'];
            if (!str_starts_with($path, '/') || $path !== parse_url($uri, PHP_URL_PATH)) {
                throw new \InvalidArgumentException('A protected resource path must match the path of its canonical resource URL.');
            }
            foreach ($resource['required_scopes'] as $scope) {
                if (!preg_match('/^[\x21\x23-\x27\x2A-\x5B\x5D-\x7E]+$/D', $scope)) {
                    throw new \InvalidArgumentException('Scopes must be individual OAuth scope tokens without parentheses.');
                }
            }
            $security['firewalls'][$name] = [
                'pattern' => '^'.preg_quote($path, '#').'$',
                'stateless' => true,
                'provider' => 'survos_resource',
                'access_token' => [
                    'token_extractors' => ['header'],
                    'token_handler' => ['oidc' => [
                        'issuers' => [$issuer],
                        'audience' => $resource['audiences'],
                        'algorithms' => ['RS256'],
                        'enforce_at_jwt_type' => true,
                        'discovery' => ['base_uri' => [rtrim($issuer, '/').'/'], 'check_issuer' => [rtrim($issuer, '/').'/' => $issuer]],
                    ]],
                    'resource_metadata' => [
                        'resource' => $uri,
                        'authorization_servers' => [$issuer],
                        'scopes_supported' => $resource['required_scopes'],
                    ],
                ],
            ];
            $security['access_control'][] = ['path' => '^'.preg_quote('/.well-known/oauth-protected-resource'.$path, '#').'$', 'roles' => 'PUBLIC_ACCESS'];
            $security['access_control'][] = ['path' => '^'.preg_quote($path, '#').'$', 'roles' => 'OAUTH2_SCOPE('.implode(' ', $resource['required_scopes']).')'];
        }
        $builder->prependExtensionConfig('security', $security);
    }

    // (removed duplicate loadExtension; logic is in the main method above)

    public function prependExtension(ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $this->prependResourceSecurity($builder);

        if ($builder->hasExtension('knpu_oauth2_client')) {
            $providers = [];
            foreach ($builder->getExtensionConfig($this->extensionAlias) as $config) {
                if (!isset($config['providers']) || !is_array($config['providers'])) {
                    continue;
                }

                foreach ($config['providers'] as $provider => $providerConfig) {
                    if (!is_array($providerConfig)) {
                        continue;
                    }

                    $providers[$provider] = array_merge($providers[$provider] ?? [], $providerConfig);
                }
            }

            if ([] !== $providers) {
                $clients = [];
                foreach ($providers as $provider => $providerConfig) {
                    if (!array_key_exists('client_id', $providerConfig) || !array_key_exists('client_secret', $providerConfig)) {
                        continue;
                    }

                    $clients[$provider] = [
                        'type' => $providerConfig['type'] ?? $provider,
                        'client_id' => $providerConfig['client_id'],
                        'client_secret' => $providerConfig['client_secret'],
                        'redirect_route' => $providerConfig['redirect_route'] ?? 'oauth_connect_check',
                        'redirect_params' => $providerConfig['redirect_params'] ?? ['clientKey' => $provider],
                    ];

                    if (array_key_exists('use_state', $providerConfig) && null !== $providerConfig['use_state']) {
                        $clients[$provider]['use_state'] = (bool) $providerConfig['use_state'];
                    }
                }

                if ([] !== $clients) {
                    $builder->prependExtensionConfig('knpu_oauth2_client', [
                        'clients' => $clients,
                    ]);
                }
            }
        }

        if (!$builder->hasExtension('ux_icons')) {
            return;
        }

        $aliases = [
            'auth' => 'mdi:shield-account',
            'github' => 'mdi:github',
            'google' => 'mdi:google',
            'facebook' => 'mdi:facebook',
            'twitter' => 'mdi:twitter',
            'user' => 'mdi:account',
            'add_user' => 'mdi:account-plus',
            'login' => 'mdi:login',
            'logout' => 'mdi:logout',
            'profile' => 'mdi:account',
            'settings' => 'mdi:cog',
            'link' => 'mdi:link',
            'unlink' => 'mdi:link-off',
        ];

        if (class_exists(\Survos\TablerBundle\SurvosTablerBundle::class)) {
            $aliases = [
                'auth' => 'tabler:shield-lock',
                'github' => 'tabler:brand-github',
                'google' => 'tabler:brand-google',
                'facebook' => 'tabler:brand-facebook',
                'twitter' => 'tabler:brand-twitter',
                'user' => 'tabler:user',
                'add_user' => 'tabler:user-plus',
                'login' => 'tabler:login',
                'logout' => 'tabler:logout',
                'profile' => 'tabler:user',
                'settings' => 'tabler:settings',
                'link' => 'tabler:link',
                'unlink' => 'tabler:unlink',
            ];
        }

        $builder->prependExtensionConfig('ux_icons', [
            'aliases' => $aliases,
        ]);
    }
}
