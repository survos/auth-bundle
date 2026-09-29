<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Service;

use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\DBAL\LockMode;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SqlitePlatform;
use Doctrine\ORM\EntityManagerInterface;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use Survos\AuthBundle\Traits\OAuthIdentifiersInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

/** Resolve a provider's stable subject to an app-owned user; email never links accounts. */
final class OAuthUserResolver
{
    public function __construct(private EntityManagerInterface $entityManager, private string $userClass) {}

    public function resolve(string $provider, ResourceOwnerInterface $identity, ?UserInterface $linkTo = null): UserInterface
    {
        $subject = (string) $identity->getId();
        if ($provider === '' || $subject === '') {
            throw new CustomUserMessageAuthenticationException('The provider did not supply an account identifier.');
        }
        if (!is_a($this->userClass, OAuthIdentifiersInterface::class, true)) {
            throw new \LogicException('The configured user must implement OAuthIdentifiersInterface and use OAuthIdentifiersTrait.');
        }
        try {
            return $this->entityManager->wrapInTransaction(function () use ($provider, $subject, $identity, $linkTo): UserInterface {
            $connection = $this->entityManager->getConnection();
            if ($connection->getDatabasePlatform() instanceof PostgreSQLPlatform) {
                // Serialize claims to a provider identity even when it has no database row yet.
                $connection->executeQuery('SELECT pg_advisory_xact_lock(hashtextextended(?, 0))', [$this->userClass . ':' . $provider . ':' . $subject]);
            }
            $existing = $this->findByProvider($provider, $subject);
            if ($existing !== null) {
                if ($linkTo !== null && $existing !== $linkTo) {
                    throw new CustomUserMessageAuthenticationException('That provider account is already connected to another account.');
                }
                return $existing;
            }
            if ($linkTo !== null) {
                if (!$linkTo instanceof $this->userClass || !$linkTo instanceof OAuthIdentifiersInterface || !$this->entityManager->contains($linkTo)) {
                    throw new \LogicException('Only a managed user of this application can link an identity.');
                }
                if ($connection->getDatabasePlatform() instanceof PostgreSQLPlatform) {
                    $this->entityManager->lock($linkTo, LockMode::PESSIMISTIC_WRITE);
                }
                $this->entityManager->refresh($linkTo);
                $linked = $linkTo->getIdentifierData($provider);
                if ($linked !== null) {
                    throw new CustomUserMessageAuthenticationException('A different account from this provider is already connected.');
                }
                $linkTo->setIdentifier($provider, $subject);
                return $linkTo;
            }
            $data = $identity->toArray();
            $email = method_exists($identity, 'getEmail') ? $identity->getEmail() : ($data['email'] ?? null);
            if (!is_string($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new CustomUserMessageAuthenticationException('The provider did not supply an email address. Please use email registration or another provider.');
            }
            $email = trim($email);
            $collision = $this->entityManager->getRepository($this->userClass)->createQueryBuilder('u')
                ->where('LOWER(u.email) = :email')->setParameter('email', mb_strtolower($email))->setMaxResults(1)
                ->getQuery()->getOneOrNullResult();
            if ($collision !== null) {
                throw new CustomUserMessageAuthenticationException('An account already uses this email. Sign in with your existing method, then connect this provider in Account settings.');
            }
            $user = new $this->userClass();
            $this->entityManager->getClassMetadata($this->userClass)->setFieldValue($user, 'email', $email);
            $user->setIdentifier($provider, $subject);
            $this->entityManager->persist($user);
            return $user;
            });
        } catch (UniqueConstraintViolationException $e) {
            throw new CustomUserMessageAuthenticationException('An account already uses this email. Sign in with your existing method, then connect this provider in Account settings.', [], 0, $e);
        }
    }

    private function findByProvider(string $provider, string $subject): ?UserInterface
    {
        $connection = $this->entityManager->getConnection();
        $metadata = $this->entityManager->getClassMetadata($this->userClass);
        $table = $connection->quoteIdentifier($metadata->getTableName());
        if ($metadata->getSchemaName()) {
            $table = $connection->quoteIdentifier($metadata->getSchemaName()) . '.' . $table;
        }
        $id = $connection->quoteIdentifier($metadata->getColumnName($metadata->getSingleIdentifierFieldName()));
        $json = $connection->quoteIdentifier($metadata->getColumnName('identifiers'));
        $platform = $connection->getDatabasePlatform();
        if ($platform instanceof PostgreSQLPlatform) {
            $expression = "COALESCE(jsonb_extract_path_text($json, :provider, 'id'), jsonb_extract_path_text($json, :provider, 'token'), CASE WHEN jsonb_typeof($json -> :provider) = 'string' THEN $json ->> :provider END)";
            $params = ['provider' => $provider, 'subject' => $subject];
        } elseif ($platform instanceof SqlitePlatform) {
            $path = '$.' . json_encode($provider, JSON_THROW_ON_ERROR);
            $expression = "COALESCE(json_extract($json, :idPath), json_extract($json, :tokenPath), CASE WHEN json_type($json, :path) = 'text' THEN json_extract($json, :path) END)";
            $params = ['path' => $path, 'idPath' => $path . '.id', 'tokenPath' => $path . '.token', 'subject' => $subject];
        } else {
            throw new \LogicException('OAuth identity lookup currently supports PostgreSQL and SQLite.');
        }
        $ids = $connection->fetchFirstColumn("SELECT $id FROM $table WHERE $expression = :subject LIMIT 2", $params);
        if (count($ids) > 1) {
            throw new CustomUserMessageAuthenticationException('This provider identity is linked more than once. Please contact support.');
        }
        return $ids === [] ? null : $this->entityManager->find($this->userClass, $ids[0]);
    }
}
