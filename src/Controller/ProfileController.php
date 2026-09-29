<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Controller;

use Doctrine\ORM\EntityManagerInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Twig\Environment;

#[IsGranted('IS_AUTHENTICATED_FULLY')]
final class ProfileController
{
    public function __construct(
        private Environment $twig,
        private TokenStorageInterface $tokenStorage,
        private EntityManagerInterface $entityManager,
        private UserPasswordHasherInterface $passwordHasher,
        private CsrfTokenManagerInterface $csrf,
        private RouterInterface $router,
        private ClientRegistry $clients,
    ) {}

    #[Route('/account', name: 'auth_profile', methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $user = $this->tokenStorage->getToken()?->getUser() ?? throw new AccessDeniedException();
        $supportsPassword = $user instanceof PasswordAuthenticatedUserInterface
            && $this->entityManager->getClassMetadata($user::class)->hasField('password');
        $error = null;
        if ($request->isMethod('POST')) {
            if (!$supportsPassword || !$this->csrf->isTokenValid(new CsrfToken('auth_password', $request->request->getString('_token')))) {
                throw new AccessDeniedException('Invalid password request.');
            }
            $password = $request->request->getString('password');
            if ($user->getPassword() !== null && !$this->passwordHasher->isPasswordValid($user, $request->request->getString('currentPassword'))) {
                $error = 'The current password is incorrect.';
            } elseif (mb_strlen($password) < 12 || strlen($password) > 4096) {
                $error = 'Use a password of at least 12 characters (at most 4096 bytes).';
            } elseif ($password !== $request->request->getString('confirmPassword')) {
                $error = 'The passwords do not match.';
            } else {
                $this->entityManager->getClassMetadata($user::class)->setFieldValue($user, 'password', $this->passwordHasher->hashPassword($user, $password));
                $this->entityManager->flush();
                $request->getSession()->getFlashBag()->add('success', 'Password saved. You can now sign in with email and password too.');
                return new RedirectResponse($this->router->generate('auth_profile'), Response::HTTP_SEE_OTHER);
            }
        }
        return new Response($this->twig->render('@SurvosAuth/profile.html.twig', [
            'supportsPassword' => $supportsPassword, 'error' => $error,
            'clientKeys' => $this->clients->getEnabledClientKeys(),
        ]), $error === null ? Response::HTTP_OK : Response::HTTP_UNPROCESSABLE_ENTITY);
    }
}
