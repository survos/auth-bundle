<?php

namespace Survos\AuthBundle\Twig\Components;

use Symfony\UX\TwigComponent\Attribute\AsTwigComponent;

#[AsTwigComponent('auth_profile', '@SurvosAuth/components/Profile.html.twig')]
final class Profile
{
    public bool $supportsPassword = false;
    public array $clientKeys = [];
    public ?string $error = null;
}
