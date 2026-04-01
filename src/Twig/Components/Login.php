<?php

namespace Survos\AuthBundle\Twig\Components;

use Symfony\UX\TwigComponent\Attribute\AsTwigComponent;

#[AsTwigComponent('auth_login', '@SurvosAuth/components/Login.html.twig')]
final class Login
{
    public bool $showOauth = true;
}
