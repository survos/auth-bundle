<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Service;

use Doctrine\ORM\EntityManagerInterface;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use Survos\AuthBundle\Traits\OAuthIdentifiersInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Resolve the claims Symfony's `oidc_login` authenticator hands a user provider to an app-owned user.
 *
 * `oidc_login` calls the firewall's user provider with the OIDC subject as identifier and every claim
 * as attributes. Call this from an AttributesBasedUserProviderInterface when isOidcLogin() is true:
 *
 *     public function loadUserByIdentifier(string $identifier, array $attributes = []): UserInterface
 *     {
 *         return OidcUserResolver::isOidcLogin($attributes)
 *             ? $this->oidcUserResolver->resolve('authentik', $attributes)
 *             : $this->findByEmail($identifier);
 *     }
 *
 * The subject is the stable key, stored in the user's identifiers like any OAuth provider's. Unlike
 * OAuthUserResolver, an account that predates SSO is linked by email the first time, but only when
 * the provider vouches for the address (`email_verified: true`); otherwise an email already in use is
 * refused rather than handed over. Only trust `email_verified` from an identity provider you run.
 */
final class OidcUserResolver
{
    public function __construct(
        private OAuthUserResolver $oauthUserResolver,
        private EntityManagerInterface $entityManager,
        private string $userClass,
    ) {
    }

    /** Whether the user provider is being called by `oidc_login` (its attributes carry the claims). */
    public static function isOidcLogin(array $attributes): bool
    {
        return isset($attributes['sub']);
    }

    /**
     * @param string               $provider key of the subject in the user's identifiers, e.g. "authentik"
     * @param array<string, mixed> $claims   the attributes `oidc_login` passed to the user provider
     */
    public function resolve(string $provider, array $claims): UserInterface
    {
        return $this->oauthUserResolver->resolve($provider, new GenericResourceOwner($claims, 'sub'), $this->findLinkableUser($provider, $claims));
    }

    /** The account a verified email names, unless it is already linked to this provider. */
    private function findLinkableUser(string $provider, array $claims): ?UserInterface
    {
        $email = $claims['email'] ?? null;
        if (true !== ($claims['email_verified'] ?? false) || !\is_string($email) || '' === trim($email)) {
            return null;
        }
        $user = $this->entityManager->getRepository($this->userClass)->createQueryBuilder('u')
            ->where('LOWER(u.email) = :email')->setParameter('email', mb_strtolower(trim($email)))->setMaxResults(1)
            ->getQuery()->getOneOrNullResult();

        return $user instanceof OAuthIdentifiersInterface && $user instanceof UserInterface && null === $user->getIdentifierData($provider) ? $user : null;
    }
}
