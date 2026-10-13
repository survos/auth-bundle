<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Twig;

use Auth;
use Twig\Extension\AbstractExtension;

class TwigExtension extends AbstractExtension
{
    public function __construct()
    {
    }

    public function getFilters(): array
    {
        return [
            //            new TwigFilter('auth', [$this, 'auth'], ['is_safe' => ['html']]),
        ];
    }

    public function getFunctions(): array
    {
        return [];
    }
}
