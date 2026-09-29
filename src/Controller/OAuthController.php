<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Survos\AuthBundle\Security\Authenticator;
use Survos\AuthBundle\Service\AuthService;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Twig\Environment;

final class OAuthController
{
    public function __construct(
        private AuthService $baseService,
        private RouterInterface $router,
        private ClientRegistry $clientRegistry,
        private Environment $twig,
        private TokenStorageInterface $tokenStorage,
        private CsrfTokenManagerInterface $csrf,
        #[Autowire('%kernel.project_dir%')] private string $projectDir,
    ) {}

    #[Route('/profile', name: 'oauth_profile', methods: ['GET'])]
    public function profile(): Response
    {
        return new RedirectResponse($this->router->generate('auth_profile'));
    }

    #[Route('/provider/{providerKey}', name: 'oauth_provider', methods: ['GET'])]
    public function providerDetail(string $providerKey): Response
    {
        $providers = $this->baseService->getCombinedOauthData();
        $provider = $providers[$providerKey] ?? throw new NotFoundHttpException('Unknown OAuth provider.');
        $details = $this->baseService->getOauthClients()[$providerKey] ?? null;
        $lock = $this->projectDir . '/composer.lock';
        $packages = is_file($lock) ? json_decode(file_get_contents($lock), true, flags: JSON_THROW_ON_ERROR)['packages'] : [];
        $package = null;
        foreach ($packages as $candidate) {
            if ($candidate['name'] === $provider['library']) $package = (object) $candidate;
        }
        if ($details['provider']['app_url'] ?? false) {
            $details['provider']['app_url'] = sprintf($details['provider']['app_url'], $details['appId']);
        }
        return new Response($this->twig->render('@SurvosAuth/oauth/provider.html.twig', [
            'provider' => $provider, 'providers' => $providers, 'providerKey' => $providerKey,
            'urls' => $details['provider'] ?? [], 'package' => $package,
            'classExists' => class_exists($provider['class']),
            'isConfigured' => in_array($providerKey, $this->clientRegistry->getEnabledClientKeys(), true),
        ]));
    }

    #[Route('/providers', name: 'oauth_providers', methods: ['GET'])]
    public function providers(): Response
    {
        $providers = $this->baseService->getCombinedOauthData();
        return new Response($this->twig->render('@SurvosAuth/oauth/providers.html.twig', ['providers' => $providers, 'clients' => $providers]));
    }

    #[Route('/social_login/{clientKey}', name: 'oauth_connect_start', methods: ['GET'])]
    public function connectAction(Request $request, string $clientKey): Response
    {
        $request->getSession()->remove(Authenticator::LINK_SESSION);
        return $this->begin($clientKey);
    }

    #[Route('/link/{clientKey}', name: 'oauth_link_start', methods: ['POST'])]
    #[IsGranted('IS_AUTHENTICATED_FULLY')]
    public function link(Request $request, string $clientKey): Response
    {
        $user = $this->tokenStorage->getToken()?->getUser();
        if ($user === null || !$this->csrf->isTokenValid(new CsrfToken('oauth_link_' . $clientKey, $request->request->getString('_token')))) {
            throw new AccessDeniedException('Invalid account connection request.');
        }
        $response = $this->begin($clientKey);
        $request->getSession()->set(Authenticator::LINK_SESSION, [
            'provider' => $clientKey, 'user' => $user->getUserIdentifier(), 'expires' => time() + 600,
            'state' => $this->clientRegistry->getClient($clientKey)->getOAuth2Provider()->getState(),
        ]);
        return $response;
    }

    #[Route('/connect/controller/{clientKey}', name: 'oauth_connect_check', methods: ['GET'])]
    public function connectCheckWithController(): never
    {
        throw new \LogicException('Register Survos\\AuthBundle\\Security\\Authenticator on the application firewall.');
    }

    private function begin(string $clientKey): RedirectResponse
    {
        if (!in_array($clientKey, $this->clientRegistry->getEnabledClientKeys(), true)) {
            throw new NotFoundHttpException('This OAuth provider is not configured.');
        }
        $scopes = $this->baseService->getProviderScopes($clientKey);
        return $this->clientRegistry->getClient($clientKey)->redirect($scopes);
    }
}
