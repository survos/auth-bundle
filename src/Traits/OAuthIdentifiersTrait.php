<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Traits;

use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Serializer\Attribute\Groups;

trait OAuthIdentifiersTrait
{
    /** @var array<string, array<string, mixed>>|null */
    #[ORM\Column(type: Types::JSONB, nullable: true)]
    #[Groups(['oauth.read'])]
    public ?array $identifiers = null {
        set {
            foreach ($value ?? [] as $provider => $identity) {
                if (!is_string($provider) || trim($provider) === '') {
                    throw new \InvalidArgumentException('An OAuth provider key must be a non-empty string.');
                }
                // Normalize the original scalar ID format when loading or assigning it.
                if (is_string($identity)) {
                    $value[$provider] = ['id' => $identity];
                } elseif (!is_array($identity)) {
                    throw new \InvalidArgumentException('An OAuth identity must be a string ID or an array.');
                }
            }
            $this->identifiers = $value;
        }
    }

    public function getIdentifiers(): ?array
    {
        return $this->identifiers;
    }

    public function getIdentifierData(string $clientKey): ?array
    {
        return $this->identifiers[$clientKey] ?? null;
    }

    public function setIdentifiers(?array $identifiers): self
    {
        $this->identifiers = $identifiers;

        return $this;
    }

    public function setIdentifier(string $clientKey, string|array $token): self
    {
        $identifiers = $this->identifiers ?? [];
        $identifiers[$clientKey] = $token;
        $this->identifiers = $identifiers;

        return $this;
    }
}
