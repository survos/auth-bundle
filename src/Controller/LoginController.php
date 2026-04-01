<?php

namespace Survos\AuthBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Twig\Environment;
use Symfony\Component\Routing\Attribute\Route;

class LoginController extends AbstractController
{
    public function __construct(private Environment $twig) {}

    #[Route('/login', name: 'auth_login', methods: ['GET'])]
    public function login(): Response
    {
        return $this->render('@SurvosAuth/login.html.twig');
    }
}
