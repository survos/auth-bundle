<?php

namespace Survos\AuthBundle\Twig\Components;

use Symfony\UX\TwigComponent\Attribute\AsTwigComponent;

#[AsTwigComponent('auth_register', '@SurvosAuth/components/Register.html.twig')]
final class Register
{
    // hook point for future customization
    public array $extraFields = [];
}
