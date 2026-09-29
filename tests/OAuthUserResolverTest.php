<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Tests;

use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Mapping as ORM;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use PHPUnit\Framework\TestCase;
use Survos\AuthBundle\Service\OAuthUserResolver;
use Survos\AuthBundle\Traits\OAuthIdentifiersInterface;
use Survos\AuthBundle\Traits\OAuthIdentifiersTrait;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

final class OAuthUserResolverTest extends TestCase
{
    private EntityManager $em;
    private OAuthUserResolver $resolver;

    protected function setUp(): void
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([__DIR__], true);
        $config->enableNativeLazyObjects(true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($this->em))->createSchema([$this->em->getClassMetadata(ResolverUser::class)]);
        $this->resolver = new OAuthUserResolver($this->em, ResolverUser::class);
    }

    private function identity(string $id, ?string $email): ResourceOwnerInterface
    {
        return new class($id, $email) implements ResourceOwnerInterface {
            public function __construct(private string $id, private ?string $email) {}
            public function getId(): string { return $this->id; }
            public function toArray(): array { return ['email' => $this->email]; }
        };
    }

    public function testNewUserNeedsNoPasswordAndReturningSubjectKeepsTheSameAccount(): void
    {
        $user = $this->resolver->resolve('google', $this->identity('123', 'reader@example.org'));
        self::assertNotNull($user->id);
        self::assertNull($user->password);
        self::assertSame(['google' => ['id' => '123']], $user->identifiers);
        $id = $user->id;
        $this->em->clear();
        $returning = $this->resolver->resolve('google', $this->identity('123', 'changed@example.org'));
        self::assertSame($id, $returning->id);
        self::assertSame('reader@example.org', $returning->email);
        self::assertSame(1, $this->em->getRepository(ResolverUser::class)->count([]));
    }

    public function testMatchingEmailNeverSilentlyLinksAccounts(): void
    {
        $this->resolver->resolve('google', $this->identity('123', 'reader@example.org'));
        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('existing method');
        $this->resolver->resolve('github', $this->identity('456', 'READER@example.org'));
    }

    public function testExplicitLinkPreservesUserAndAllowsDifferentProviderEmail(): void
    {
        $user = $this->resolver->resolve('google', $this->identity('123', 'reader@example.org'));
        $linked = $this->resolver->resolve('github', $this->identity('456', 'other@example.org'), $user);
        self::assertSame($user, $linked);
        self::assertSame(['id' => '456'], $linked->getIdentifierData('github'));
        self::assertSame(1, $this->em->getRepository(ResolverUser::class)->count([]));
    }

    public function testProviderIdentityCannotBeLinkedToAnotherUser(): void
    {
        $first = $this->resolver->resolve('google', $this->identity('123', 'first@example.org'));
        $this->resolver->resolve('github', $this->identity('456', 'second@example.org'));
        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->resolver->resolve('github', $this->identity('456', 'second@example.org'), $first);
    }

    public function testExistingProviderCannotBeOverwrittenWithAnotherSubject(): void
    {
        $user = $this->resolver->resolve('google', $this->identity('123', 'reader@example.org'));
        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->resolver->resolve('google', $this->identity('456', 'reader@example.org'), $user);
    }

    public function testMissingEmailIsRejectedForNewAccounts(): void
    {
        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->resolver->resolve('google', $this->identity('123', null));
    }

    public function testLegacyScalarAndTokenRecordsStillResolve(): void
    {
        $user = $this->resolver->resolve('google', $this->identity('123', 'reader@example.org'));
        $this->em->getConnection()->executeStatement('UPDATE ResolverUser SET identifiers = ?', [json_encode(['google' => '123', 'github' => ['token' => '456']])]);
        $id = $user->id;
        $this->em->clear();
        self::assertSame($id, $this->resolver->resolve('google', $this->identity('123', null))->id);
        self::assertSame($id, $this->resolver->resolve('github', $this->identity('456', null))->id);
    }
}

#[ORM\Entity]
class ResolverUser implements UserInterface, OAuthIdentifiersInterface
{
    use OAuthIdentifiersTrait;
    #[ORM\Id, ORM\GeneratedValue, ORM\Column]
    public ?int $id = null;
    #[ORM\Column(unique: true)]
    public string $email;
    #[ORM\Column(nullable: true)]
    public ?string $password = null;
    public function getUserIdentifier(): string { return $this->email; }
    public function getRoles(): array { return ['ROLE_USER']; }
    public function eraseCredentials(): void {}
}
