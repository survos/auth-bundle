<?php

namespace Survos\AuthBundle\Service;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\DependencyInjection\ProviderFactory;
use Psr\Log\LoggerInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Yaml\Yaml;
use Symfony\Component\Security\Core\User\UserInterface;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use Survos\AuthBundle\Traits\OAuthIdentifiersInterface;
use Symfony\Component\HttpFoundation\RequestStack;

class AuthService
{
    public function __construct(
        private string $userClass,
        private array $config,
        private ClientRegistry $clientRegistry,
        private ?LoggerInterface $logger=null,
        private ?RequestStack $requestStack = null

        //        private ProviderFactory $provider
    ) {
        //        $this->clientRegistry = $clientRegistry;
        //        $this->provider = $provider;
        //        $this->userClass = $userClass;
    }

    public function allowLogin(): bool
    {
        return $this->config['allow_login'] !== 'none';
    }

    public function getUserClass(): string
    {
        return $this->userClass;
    }

    public function getOauthClientKeys(): ?array
    {
        return $this->clientRegistry->getEnabledClientKeys();
    }

    public function getProviderUser(string $clientKey, string $accessToken)
    {
        if (!$client = $this->clientRegistry->getClient($clientKey)) {
            $this->logger->error("bad client " . $clientKey);
        }
        assert($client, "bad client " . $clientKey);

        // from session?
        $accessToken = $client->getAccessToken();
        $user = $client->fetchUserFromToken($accessToken);
        return $user;

//        $user = $this->userProvider->loadUserByIdentifier($email);


    }

    // hack to get client id
    private function accessProtected($obj, $prop)
    {
        $reflection = new \ReflectionClass($obj);
        // dump($obj, $prop);
        try {
            $property = $reflection->getProperty($prop);
            $property->setAccessible(true);
            return $property->getValue($obj);
        } catch (\Exception $e) {
            // log the error?
            return false;
        }
    }

    public function getOauthClients($all = false): array
    {
        // links to accont info
        $providers = $this->getOAuthProviderUrls();

        // really need to get all TYPES (facebookId, etc.), then group the clients under them, plus have the provider data.
        // eventually we'll want an admin client to display the related apps

        $keys = $this->clientRegistry->getEnabledClientKeys();

        return array_combine($keys, array_map(function ($key) use ($providers) {
            $client = $this->clientRegistry->getClient($key);
            $provider = $client->getOAuth2Provider();
            $clientId = $this->accessProtected($client->getOAuth2Provider(), 'clientId');
            try {
            $type = $this->accessProtected($client->getOAuth2Provider(), 'type');
            if (!$type) {
                $this->logger->error($msg = "Missing property 'type' in $key " );
//                dd($msg, $provider, $client->getOAuth2Provider());
            }
            } catch (\Exception $e) {
                $client = false;
                $provider = false;
            }
            // $extra = $this->accessProtected($provider, 'extrias');
            return [
                'key' => $key,
                'provider' => $providers[$key],
                'client' => $client,
                'appId' => $clientId,
                // 'type' => $type
            ];
        }, $keys));
    }

    public function getClientRegistry(): ClientRegistry
    {
        return $this->clientRegistry;
    }

    // Central entry point for OAuth user resolution
    public function getOrCreateUser(string $provider, ResourceOwnerInterface $oauthUser): UserInterface
    {
        $userClass = $this->userClass;

        $data = method_exists($oauthUser, 'toArray') ? $oauthUser->toArray() : [];
        $email = method_exists($oauthUser, 'getEmail')
            ? $oauthUser->getEmail()
            : ($data['email'] ?? null);

        $identifier = $oauthUser->getId();

        // naive lookup by email first
        $repo = (new \ReflectionClass($userClass))->newInstanceWithoutConstructor();
        // we cannot access EM here safely without adding deps, so delegate via trait expectations

        // expectation: user provider or repository handles lookup; fallback create
        // minimal approach: always create new instance and let app override later
        /** @var UserInterface&OAuthIdentifiersInterface $user */
        $user = new $userClass();

        if (method_exists($user, 'setEmail') && $email) {
            $user->setEmail($email);
        }

        if ($user instanceof OAuthIdentifiersInterface) {
            $user->setIdentifier($provider, $identifier);
        }

        // Apply extra registration fields from session via RequestStack
        if ($this->requestStack && ($session = $this->requestStack->getSession())) {
            if ($session->has('auth_extra_fields')) {
                $extra = $session->get('auth_extra_fields', []);
                foreach ($extra as $key => $value) {
                    $setter = 'set' . ucfirst($key);
                    if (method_exists($user, $setter)) {
                        $user->$setter($value);
                    }
                }
                $session->remove('auth_extra_fields');
            }
        }

        return $user;
    }

    // expose authenticator for controller
    public function getAuthenticator()
    {
        // rely on container autowiring alias for Authenticator class
        return new \Survos\AuthBundle\Security\Authenticator(
            $this->clientRegistry,
            null,
            null,
            $this->userClass,
            null
        );
    }

    // the hand-curated list of URLs.  Written by hand
    protected static function getOAuthProviderUrlPath(): string
    {
        return __DIR__ . '/../../data/oauth_provider_urls.yaml';
    }

    // the data from KNPU's list of providers plus the urls to link to for configurating.
    // written by survos:fetch-oauth-providers,
    // when read by AuthService::authProviderData.  Does NOT include project-specific data
    // when read by AuthService->authProviderConfigurationData.  Does include project-specific data (needs ClientRegistry)
    protected static function getOAuthProviderCombinedPath(): string
    {
        return __DIR__ . '/../../data/oauth_provider.yaml';
    }

    public function writeCombinedOauthData($data)
    {
        file_put_contents(
            $fn = self::getOAuthProviderCombinedPath(),
            sprintf(
                "#  automatically recreated, merges data from knp oauth client bundle  and %s\n\n%s",
                self::getOAuthProviderUrlPath(),
                Yaml::dump([
                    'providers' => $data,
                ], 3, 4, Yaml::DUMP_MULTI_LINE_LITERAL_BLOCK)
            )
        );

        return $fn;
    }

    // returns array of providers, by key.  Includes a 'clients' key with configured clients
    public function getCombinedOauthData(): array
    {
        $providers = Yaml::parseFile(self::getOAuthProviderCombinedPath())['providers'];
        // set some defaults
        $resolver = (new OptionsResolver())
            ->setDefaults([
                'clients' => [],
                'user_apps' => null,
                'app_url' => null,
                'apps_url' => null,
                'admin_url' => null,
                'user_url' => null,
                'comments' => null,
                'client_id' => null,
                'client_secret' => null,
                'class' => null,
                'library' => null,
                'type' => null,
            ]);

        $classToTypeMap = [];
        foreach (array_keys($providers) as $key) {
            $provider = $resolver->resolve($providers[$key]);

            // map the class to the type, since the client information lacks a type

            // get the environment vars
            $comments = $provider['comments'];
            if (preg_match_all('/env\(([^\)]+)\)/', $comments, $m)) {
                $provider['env_vars'] = $m[1];
            } else {
                assert(false, "Bad match: " . $comments);
            }

            $classToTypeMap[$provider['class']] = $provider['type'];

            // hack to fix the routes
            $comments = str_replace(sprintf('connect_%s_check', $key), 'oauth_connect_check', $comments);
            $comments = str_replace('redirect_params: {}', "redirect_params: { clientKey: $key}  # MUST match the client key above", $comments);
            $provider['comments'] = $comments;

            $providers[$key] = $provider;
            // throw new \Exception($provider, $classToTypeMap);
        }
        /* not sure why this doesn't work
        array_walk(array_keys($providers), function ($key) use ($providers, $resolver) {
            // $providers[$key]['clients'] = [];
            // $data['clients'] = [];
            $providers[$key] = $resolver->resolve($providers[$key]);
            if ($key === 'amazon') dump($providers[$key]);
        });
        */

        // go through all the providers and look for their TYPE
        $providerClients = [];
        foreach ($this->clientRegistry->getEnabledClientKeys() as $key) {
            $client = $this->clientRegistry->getClient($key);
            $clientProvider = $client->getOAuth2Provider();
            $class = get_class($client); // the Knpu class
            $providerClass = get_class($clientProvider);

            $type = $classToTypeMap[$class];
            if (! key_exists($type, $providers)) {
                throw new \Exception("Missing $type ($class) in providers");
            }
            // throw new \Exception($class, $client, $clientProvider, $type, $providerClass);

            $providers[$type]['clients'][$key] = $client;
        }

        /*
        $clients = array_map(function ($key) use ($providers) {
            return [
                'key' => $key,
                'config' => $providers[$key],
                'clients' => $providerClients[strtolower($key)] ?? false
            ];
        }, array_keys($providers));
        */
        return $providers;
    }

    public function getOAuthProviderUrls()
    {
        return Yaml::parseFile(self::getOAuthProviderUrlPath())['providers'];
    }
}
