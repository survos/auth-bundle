<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Security;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
use Survos\AuthBundle\Service\OAuthUserResolver;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

final class Authenticator extends OAuth2Authenticator implements AuthenticationEntryPointInterface
{
    use TargetPathTrait;

    public const LINK_SESSION = 'survos_auth.link';

    public function __construct(
        private ClientRegistry $clientRegistry,
        private OAuthUserResolver $userResolver,
        private RouterInterface $router,
        private TokenStorageInterface $tokenStorage,
        private string $newUserRedirectRoute,
        private string $loginRoute,
    ) {}

    public function supports(Request $request): bool
    {
        return $request->attributes->get('_route') === 'oauth_connect_check';
    }

    public function authenticate(Request $request): Passport
    {
        $provider = $request->attributes->getString('clientKey');
        $pending = $request->getSession()->remove(self::LINK_SESSION);
        if ($request->query->has('error')) {
            throw new CustomUserMessageAuthenticationException('Sign-in was cancelled or declined. Please try again.');
        }
        $client = $this->clientRegistry->getClient($provider);
        $accessToken = $this->fetchAccessToken($client);
        $identity = $client->fetchUserFromToken($accessToken);
        $linkTo = null;
        if ($pending !== null) {
            $linkTo = $this->tokenStorage->getToken()?->getUser();
            if (!is_array($pending) || $linkTo === null || ($pending['provider'] ?? null) !== $provider
                || ($pending['user'] ?? null) !== $linkTo->getUserIdentifier()
                || ($pending['expires'] ?? 0) < time()
                || !hash_equals((string) ($pending['state'] ?? ''), $request->query->getString('state'))) {
                throw new CustomUserMessageAuthenticationException('The account connection expired. Please start again from Account settings.');
            }
            $request->attributes->set('_survos_auth_linking', true);
        }
        return new SelfValidatingPassport(new UserBadge(
            $provider . ':' . $identity->getId(),
            fn () => $this->userResolver->resolve($provider, $identity, $linkTo),
        ));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        if ($request->attributes->get('_survos_auth_linking')) {
            return new RedirectResponse($this->router->generate('auth_profile'));
        }
        if ($target = $this->getTargetPath($request->getSession(), $firewallName)) {
            $this->removeTargetPath($request->getSession(), $firewallName);
            return new RedirectResponse($target);
        }
        return new RedirectResponse($this->router->generate($this->newUserRedirectRoute));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $request->getSession()->remove(self::LINK_SESSION);
        $message = $exception instanceof CustomUserMessageAuthenticationException
            ? $exception->getMessageKey() : 'Unable to sign in. Please start again.';
        $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, new CustomUserMessageAuthenticationException($message));
        return new RedirectResponse($this->router->generate($this->loginRoute));
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return new RedirectResponse($this->router->generate($this->loginRoute));
    }
}
