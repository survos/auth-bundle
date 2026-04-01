<?php

namespace Survos\AuthBundle\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Environment;

class ProfileController
{
    #[Route('/profile', name: 'auth_profile', methods: ['GET'])]
    public function __invoke(Environment $twig): Response
    {
        return new Response($twig->render('@SurvosAuth/profile.html.twig'));
    }
}
