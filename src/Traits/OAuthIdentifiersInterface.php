<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Traits;


interface OAuthIdentifiersInterface
{

    const GITHUB = 'github';

    public function getIdentifiers(): ?array;
    public function getIdentifierData(string $clientKey): ?array;
    public function setIdentifiers(?array $identifiers): self;
    public function setIdentifier(string $clientKey, string|array $token): self;

}
