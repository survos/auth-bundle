<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Survos\AuthBundle\Security\ResourcePrincipal;
use Survos\AuthBundle\Security\ResourceUserProvider;
use Survos\AuthBundle\SurvosAuthBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

final class ResourceSecurityTest extends TestCase
{
    public const ISSUER = 'https://issuer.example/application/o/corpus/';
    public const RESOURCE = 'https://harvest.example/mcp/corpus';
    private static \OpenSSLAsymmetricKey $key;
    public static array $jwk;
    private ResourceSecurityKernel $kernel;

    public static function setUpBeforeClass(): void
    {
        self::$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $details = openssl_pkey_get_details(self::$key);
        self::$jwk = ['kty' => 'RSA', 'kid' => 'test-key', 'use' => 'sig', 'alg' => 'RS256',
            'n' => self::base64($details['rsa']['n']), 'e' => self::base64($details['rsa']['e'])];
    }

    protected function setUp(): void
    {
        $this->kernel = new ResourceSecurityKernel('test', true);
        $this->kernel->boot();
    }

    protected function tearDown(): void
    {
        $this->kernel->shutdown();
    }

    public static function configuration(array $overrides = []): array
    {
        return ['authorities' => ['test' => ['issuer' => self::ISSUER]], 'resources' => ['corpus' => array_replace([
            'authority' => 'test', 'path' => '/mcp/corpus', 'resource' => self::RESOURCE,
            'audiences' => [self::RESOURCE], 'required_scopes' => ['corpus:read'],
        ], $overrides)]];
    }

    public static function project(array $config): array
    {
        $builder = new ContainerBuilder();
        $builder->registerExtension(new SecurityExtension());
        $extension = (new SurvosAuthBundle())->getContainerExtension();
        $builder->registerExtension($extension);
        $builder->loadFromExtension('survos_auth', $config);
        $extension->prepend($builder);

        return $builder->getExtensionConfig('security');
    }

    public function testAbsentAndDisabledConfigurationDoesNotChangeSecurity(): void
    {
        self::assertSame([], self::project([]));
        self::assertSame([], self::project(self::configuration(['enabled' => false])));
    }

    public function testUnknownAuthorityFailsCompilation(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        self::project(self::configuration(['authority' => 'unknown']));
    }

    public function testMetadataIsPublicAndUsesConfiguredOrigin(): void
    {
        $response = $this->kernel->handle(Request::create('https://untrusted.example/.well-known/oauth-protected-resource/mcp/corpus'));
        self::assertSame(200, $response->getStatusCode());
        $data = json_decode($response->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame(self::RESOURCE, $data['resource']);
        self::assertSame([self::ISSUER], $data['authorization_servers']);
        self::assertSame(['corpus:read'], $data['scopes_supported']);
    }

    public function testMissingTokenAndCookieCannotBypassAuthentication(): void
    {
        $request = Request::create(self::RESOURCE, 'POST', cookies: ['PHPSESSID' => 'pretend-browser-session']);
        $response = $this->kernel->handle($request);
        self::assertSame(401, $response->getStatusCode());
        self::assertFalse($response->headers->has('Location'));
        self::assertStringContainsString('https://harvest.example/.well-known/oauth-protected-resource/mcp/corpus', $response->headers->get('WWW-Authenticate'));
    }

    public function testValidTokenHasNoApplicationRolesAndDoesNotPersistAuthentication(): void
    {
        $response = $this->request(self::token(['roles' => ['ROLE_SUPER_ADMIN']]));
        self::assertSame(200, $response->getStatusCode(), $response->getContent());
        $data = json_decode($response->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame([], $data['roles']);
        self::assertSame(ResourcePrincipal::class, $data['class']);
        self::assertSame([self::ISSUER, 'service-123'], json_decode($data['identifier'], true));
        self::assertSame(401, $this->kernel->handle(Request::create(self::RESOURCE))->getStatusCode());
    }

    public function testMissingScopeIsForbiddenNotUnauthenticated(): void
    {
        $response = $this->request(self::token(['scope' => 'profile']));
        self::assertSame(403, $response->getStatusCode());
        self::assertStringContainsString('insufficient_scope', $response->headers->get('WWW-Authenticate'));
        self::assertStringContainsString('corpus:read', $response->headers->get('WWW-Authenticate'));
    }

    #[DataProvider('badTokens')]
    public function testInvalidTokensAreRejected(array $claims, array $header, ?string $remove): void
    {
        $response = $this->request(self::token($claims, $header, $remove));
        self::assertSame(401, $response->getStatusCode());
        self::assertFalse($response->headers->has('Location'));
    }

    public static function badTokens(): iterable
    {
        yield 'wrong issuer' => [['iss' => 'https://other.example/'], [], null];
        yield 'wrong audience' => [['aud' => 'browser-client'], [], null];
        yield 'expired' => [['exp' => 1], [], null];
        yield 'future nbf' => [['nbf' => 4102444800], [], null];
        yield 'missing expiry' => [[], [], 'exp'];
        yield 'missing issuer' => [[], [], 'iss'];
        yield 'missing audience' => [[], [], 'aud'];
        yield 'missing subject' => [[], [], 'sub'];
        yield 'ID token' => [[], ['typ' => 'JWT'], null];
        yield 'none algorithm' => [[], ['alg' => 'none'], null];
        yield 'sender constrained token' => [['cnf' => ['jkt' => 'bound-to-another-key']], [], null];
    }

    public function testTamperedSignatureIsRejected(): void
    {
        $token = self::token();
        [$header, $payload, $signature] = explode('.', $token);
        $signature[0] = 'A' === $signature[0] ? 'B' : 'A';
        self::assertSame(401, $this->request("$header.$payload.$signature")->getStatusCode());
    }

    private function request(string $token): \Symfony\Component\HttpFoundation\Response
    {
        return $this->kernel->handle(Request::create(self::RESOURCE, 'POST', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]));
    }

    public static function token(array $claims = [], array $header = [], ?string $remove = null): string
    {
        $claims = array_replace(['iss' => self::ISSUER, 'aud' => self::RESOURCE, 'sub' => 'service-123',
            'iat' => time(), 'exp' => time() + 120, 'scope' => 'corpus:read'], $claims);
        if (null !== $remove) {
            unset($claims[$remove]);
        }
        $input = self::base64(json_encode(array_replace(['alg' => 'RS256', 'typ' => 'at+jwt', 'kid' => 'test-key'], $header), JSON_THROW_ON_ERROR)).'.'.self::base64(json_encode($claims, JSON_THROW_ON_ERROR));
        openssl_sign($input, $signature, self::$key, OPENSSL_ALGO_SHA256);

        return $input.'.'.self::base64($signature);
    }

    private static function base64(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    public static function httpClient(): MockHttpClient
    {
        return new MockHttpClient(static function (string $method, string $url): MockResponse {
            $data = match ($url) {
                self::ISSUER.'.well-known/openid-configuration' => ['issuer' => self::ISSUER, 'jwks_uri' => self::ISSUER.'jwks/'],
                self::ISSUER.'jwks/' => ['keys' => [self::$jwk]],
                default => throw new \LogicException('Unexpected network request: '.$url),
            };

            return new MockResponse(json_encode($data, JSON_THROW_ON_ERROR));
        });
    }
}

final class ResourceSecurityKernel extends Kernel
{
    use MicroKernelTrait;

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new SecurityBundle();
    }

    public function getCacheDir(): string
    {
        return ($_SERVER['AUTH_TEST_CACHE'] ?? sys_get_temp_dir().'/survos-resource-tests').'/'.getmypid();
    }

    public function getLogDir(): string
    {
        return $this->getCacheDir();
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', ['secret' => 'test-only', 'router' => ['utf8' => true], 'http_client' => true]);
        $security = ResourceSecurityTest::project(ResourceSecurityTest::configuration())[0];
        $security['firewalls']['main'] = ['security' => false];
        $container->extension('security', $security);
        $container->services()->set(ResourceUserProvider::class);
        $container->services()->set('logger', \Psr\Log\NullLogger::class);
        $container->services()->set('http_client', MockHttpClient::class)->factory([ResourceSecurityTest::class, 'httpClient']);
        $container->services()->set(ResourceTestController::class)->autowire()->public();
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import('security.route_loader', 'service');
        $routes->add('corpus', '/mcp/corpus')->controller(ResourceTestController::class);
    }
}

final readonly class ResourceTestController
{
    public function __construct(private TokenStorageInterface $tokens)
    {
    }

    public function __invoke(): JsonResponse
    {
        $user = $this->tokens->getToken()->getUser();

        return new JsonResponse(['roles' => $user->getRoles(), 'identifier' => $user->getUserIdentifier(), 'class' => $user::class]);
    }
}
