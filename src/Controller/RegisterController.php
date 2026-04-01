<?php

namespace Survos\AuthBundle\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Environment;
use Survos\AuthBundle\Service\AuthService;
use Symfony\Component\HttpFoundation\RedirectResponse;

class RegisterController
{
    public function __construct(
        private Environment $twig,
        private AuthService $authService
    ) {}

    #[Route('/register', name: 'auth_register', methods: ['GET','POST'])]
    public function __invoke(Request $request): Response
    {
        if ($request->isMethod('POST')) {
            $request->getSession()->set('auth_extra_fields', $request->request->all());
            // Redirect to login so user can pick a provider immediately
            return new RedirectResponse('/auth/login');
        }

        return new Response($this->twig->render('@SurvosAuth/register.html.twig'));
    }
}
