<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Tests;

use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;
use Survos\AuthBundle\Service\OAuthUserResolver;
use Survos\AuthBundle\Service\OidcUserResolver;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

require_once __DIR__.'/OAuthUserResolverTest.php';

final class OidcUserResolverTest extends TestCase
{
    private EntityManager $em;
    private OidcUserResolver $resolver;

    protected function setUp(): void
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([__DIR__], true);
        $config->enableNativeLazyObjects(true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($this->em))->createSchema([$this->em->getClassMetadata(ResolverUser::class)]);
        $this->resolver = new OidcUserResolver(new OAuthUserResolver($this->em, ResolverUser::class), $this->em, ResolverUser::class);
    }

    private function existing(string $email): ResolverUser
    {
        $user = new ResolverUser();
        $user->email = $email;
        $this->em->persist($user);
        $this->em->flush();

        return $user;
    }

    public function testOnlyTheClaimsOfOidcLoginCountAsOidc(): void
    {
        self::assertTrue(OidcUserResolver::isOidcLogin(['sub' => 'abc', 'email' => 'a@example.org']));
        self::assertFalse(OidcUserResolver::isOidcLogin([]));
    }

    public function testNewSubjectCreatesAUserAndReturnsItAgain(): void
    {
        $user = $this->resolver->resolve('authentik', ['sub' => 'abc', 'email' => 'new@example.org', 'email_verified' => true]);
        self::assertSame('new@example.org', $user->email);
        self::assertSame(['authentik' => ['id' => 'abc']], $user->identifiers);

        $this->em->clear();
        self::assertSame($user->id, $this->resolver->resolve('authentik', ['sub' => 'abc', 'email' => 'changed@example.org'])->id);
    }

    public function testVerifiedEmailLinksTheExistingAccountCaseInsensitively(): void
    {
        $existing = $this->existing('Reader@Example.org');

        $user = $this->resolver->resolve('authentik', ['sub' => 'abc', 'email' => 'reader@example.org', 'email_verified' => true]);

        self::assertSame($existing->id, $user->id);
        self::assertSame(['authentik' => ['id' => 'abc']], $user->identifiers);
    }

    public function testUnverifiedEmailNeverHandsOverAnExistingAccount(): void
    {
        $this->existing('reader@example.org');

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->resolver->resolve('authentik', ['sub' => 'abc', 'email' => 'reader@example.org', 'email_verified' => false]);
    }

    public function testAnAccountLinkedToAnotherSubjectIsNotRelinked(): void
    {
        $this->resolver->resolve('authentik', ['sub' => 'first', 'email' => 'reader@example.org', 'email_verified' => true]);

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->resolver->resolve('authentik', ['sub' => 'second', 'email' => 'reader@example.org', 'email_verified' => true]);
    }
}
