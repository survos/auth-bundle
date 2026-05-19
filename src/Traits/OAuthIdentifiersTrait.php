<?php

namespace Survos\AuthBundle\Traits;

use Doctrine\DBAL\Types\Types;
use Symfony\Component\Serializer\Attribute\Groups;
use Doctrine\ORM\Mapping as ORM;

trait OAuthIdentifiersTrait
{

    #[ORM\Column(type: Types::JSONB, nullable: true)]
    #[Groups(['oauth.read'])]
    private ?array $identifiers=null;

    public function getIdentifiers(): ?array
    {
        return $this->identifiers;
    }

    public function getIdentifierData(string $clientKey): ?array
    {
        return $this->getIdentifiers()[$clientKey]??null;

    }

    public function setIdentifiers(?array $identifiers): self
    {
        $this->identifiers = $identifiers;
        return $this;
    }
    public function setIdentifier(string $clientKey, string|array $token): self
    {
        $this->identifiers[$clientKey] = $token;
        return $this;
    }

}
