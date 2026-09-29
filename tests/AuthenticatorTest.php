<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Tests;

use Doctrine\ORM\EntityManagerInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Exception\InvalidStateException;
use KnpU\OAuth2ClientBundle\Security\Exception\InvalidStateAuthenticationException;
use PHPUnit\Framework\TestCase;
use Survos\AuthBundle\Security\Authenticator;
use Survos\AuthBundle\Service\OAuthUserResolver;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

final class AuthenticatorTest extends TestCase
{
    private function request(string $query = ''): Request
    {
        $request = Request::create('/auth/connect/controller/google' . $query);
        $request->attributes->add(['_route' => 'oauth_connect_check', 'clientKey' => 'google']);
        $request->setSession(new Session(new MockArraySessionStorage()));
        return $request;
    }

    private function authenticator(?ClientRegistry $registry = null, ?RouterInterface $router = null): Authenticator
    {
        return new Authenticator(
            $registry ?? $this->createStub(ClientRegistry::class),
            new OAuthUserResolver($this->createStub(EntityManagerInterface::class), 'unused'),
            $router ?? $this->createStub(RouterInterface::class), new TokenStorage(), 'ink_home', 'app_login',
        );
    }

    public function testCancellationDoesNotExchangeCodeAndClearsLinkIntent(): void
    {
        $registry = $this->createMock(ClientRegistry::class);
        $registry->expects(self::never())->method('getClient');
        $request = $this->request('?error=access_denied');
        $request->getSession()->set(Authenticator::LINK_SESSION, ['provider' => 'google']);
        try {
            $this->authenticator($registry)->authenticate($request);
            self::fail('Cancellation must fail authentication.');
        } catch (CustomUserMessageAuthenticationException $e) {
            self::assertStringContainsString('cancelled', $e->getMessageKey());
            self::assertFalse($request->getSession()->has(Authenticator::LINK_SESSION));
        }
    }

    public function testInvalidStateFailsBeforeFetchingIdentityAndQueryCannotChooseProvider(): void
    {
        $client = $this->createMock(OAuth2ClientInterface::class);
        $client->method('getAccessToken')->willThrowException(new InvalidStateException());
        $client->expects(self::never())->method('fetchUserFromToken');
        $registry = $this->createMock(ClientRegistry::class);
        $registry->expects(self::once())->method('getClient')->with('google')->willReturn($client);
        $this->expectException(InvalidStateAuthenticationException::class);
        $this->authenticator($registry)->authenticate($this->request('?clientKey=github&state=wrong'));
    }

    public function testFailureDoesNotExposeCallbackParametersOrRawException(): void
    {
        $router = $this->createMock(RouterInterface::class);
        $router->expects(self::once())->method('generate')->with('app_login')->willReturn('/login');
        $request = $this->request('?code=secret-code&state=secret-state');
        $response = $this->authenticator(router: $router)->onAuthenticationFailure($request, new AuthenticationException('provider secret'));
        self::assertSame('/login', $response->headers->get('Location'));
        $error = $request->getSession()->get(SecurityRequestAttributes::AUTHENTICATION_ERROR);
        self::assertSame('Unable to sign in. Please start again.', $error->getMessageKey());
        self::assertStringNotContainsString('secret', serialize($error));
    }

    public function testSuccessDoesNotAppendUserEmailToRedirect(): void
    {
        $router = $this->createMock(RouterInterface::class);
        $router->expects(self::once())->method('generate')->with('ink_home', [])->willReturn('/');
        $response = $this->authenticator(router: $router)->onAuthenticationSuccess($this->request(), $this->createStub(TokenInterface::class), 'main');
        self::assertSame('/', $response->headers->get('Location'));
    }
}
