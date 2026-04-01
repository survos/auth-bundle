<?php

namespace Survos\AuthBundle\Twig\Components;

use Survos\AuthBundle\Service\AuthService;
use Symfony\UX\TwigComponent\Attribute\AsTwigComponent;

#[AsTwigComponent('OAuth', '@SurvosAuth/components/OAuth.html.twig')]
final class OAuth
{
    public string $buttonClass='btn btn-primary';

    // <i class="bi bi-github"></i>
    public string $iconPrefix='bi bi-'; // hack

    public function __construct(private AuthService $authService)
    {
        // detect Tabler and adjust default classes
        if (class_exists(\Survos\TablerBundle\SurvosTablerBundle::class)) {
            $this->buttonClass = 'btn btn-outline-primary w-100 mb-2';
        }
    }

    public function getClientKeys(): array
    {
        return $this->authService->getOauthClientKeys() ?? [];
    }

    public function getKnownProviders(): array
    {
        return ['github','google','facebook','twitter'];
    }

    public function getMissingProviders(): array
    {
        $enabled = $this->getClientKeys();
        return array_values(array_diff($this->getKnownProviders(), $enabled));
    }
}
