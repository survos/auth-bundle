<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Security;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\AttributesBasedUserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/** Stateless principals from already validated access tokens, never browser accounts. */
final class ResourceUserProvider implements AttributesBasedUserProviderInterface
{
    public const ISSUER = 'iss';
    public const SUBJECT = 'sub';

    public function loadUserByIdentifier(string $identifier, array $attributes = []): UserInterface
    {
        foreach ([self::ISSUER, self::SUBJECT] as $claim) {
            if (!isset($attributes[$claim]) || !is_string($attributes[$claim]) || '' === $attributes[$claim]) {
                throw new UserNotFoundException('Missing resource principal identity.');
            }
        }
        if ($identifier !== $attributes[self::SUBJECT]) {
            throw new UserNotFoundException('Resource principal subject mismatch.');
        }

        return new ResourcePrincipal($attributes[self::ISSUER], $attributes[self::SUBJECT]);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        throw new UnsupportedUserException('Resource principals must be authenticated on every request.');
    }

    public function supportsClass(string $class): bool
    {
        return ResourcePrincipal::class === $class;
    }
}
