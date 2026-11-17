<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;

/** A resource identity carries no application roles, email linking or persisted account. */
final readonly class ResourcePrincipal implements UserInterface
{
    public function __construct(public string $issuer, public string $subject)
    {
    }

    public function getUserIdentifier(): string
    {
        return json_encode([$this->issuer, $this->subject], JSON_THROW_ON_ERROR);
    }

    public function getRoles(): array
    {
        return [];
    }

    public function eraseCredentials(): void
    {
    }
}
