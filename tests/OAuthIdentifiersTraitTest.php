<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Tests;

use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Mapping as ORM;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;
use Survos\AuthBundle\Traits\OAuthIdentifiersInterface;
use Survos\AuthBundle\Traits\OAuthIdentifiersTrait;

final class OAuthIdentifiersTraitTest extends TestCase
{
    public function testProvidersShareOneFieldAndUpdatesPreserveOtherProviders(): void
    {
        $user = new OAuthTestUser();
        $user->setIdentifier('google', 'g1')->setIdentifier('github', 'h1');
        $user->setIdentifier('google', 'g2');
        self::assertSame(['google' => ['id' => 'g2'], 'github' => ['id' => 'h1']], $user->identifiers);
        self::assertNull($user->getIdentifierData('facebook'));
    }

    public function testLegacyStringsNormalizeAndArrayRecordsSurvive(): void
    {
        $user = new OAuthTestUser();
        $legacy = ['token' => 'old-id', 'data' => ['name' => 'Example']];
        $user->identifiers = ['google' => '123', 'facebook' => $legacy];
        self::assertSame(['id' => '123'], $user->getIdentifierData('google'));
        self::assertSame($legacy, $user->getIdentifierData('facebook'));
        $user->setIdentifiers(null);
        self::assertNull($user->getIdentifiers());
    }

    public function testInvalidIdentityDoesNotReplaceExistingData(): void
    {
        $user = new OAuthTestUser();
        $user->setIdentifier('google', '123');
        try {
            $user->identifiers = ['google' => false];
            self::fail('Expected invalid identity to be rejected.');
        } catch (\InvalidArgumentException) {
            self::assertSame(['google' => ['id' => '123']], $user->identifiers);
        }
    }

    public function testDoctrinePersistsAndHydratesTheHookedJsonField(): void
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([__DIR__], true);
        $config->enableNativeLazyObjects(true);
        $em = new EntityManager(
            DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]),
            $config,
        );
        $metadata = $em->getClassMetadata(OAuthTestUser::class);
        (new SchemaTool($em))->createSchema([$metadata]);
        $user = new OAuthTestUser();
        $user->setIdentifier('google', '123')->setIdentifier('github', '456');
        $em->persist($user);
        $em->flush();
        $id = $user->id;
        $em->clear();
        $loaded = $em->find(OAuthTestUser::class, $id);
        self::assertSame(['id' => '123'], $loaded->getIdentifierData('google'));
        $loaded->setIdentifier('facebook', '789');
        $em->flush();
        $em->clear();
        self::assertCount(3, $em->find(OAuthTestUser::class, $id)->identifiers);
        $em->close();
    }
}

#[ORM\Entity]
final class OAuthTestUser implements OAuthIdentifiersInterface
{
    use OAuthIdentifiersTrait;

    #[ORM\Id, ORM\GeneratedValue, ORM\Column]
    public ?int $id = null;
}
