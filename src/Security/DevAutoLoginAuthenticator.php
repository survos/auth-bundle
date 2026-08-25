<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Security;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * Logs every request in as a fixed user, so admin UIs are usable in dev without a login form.
 *
 * These apps are deny-by-default (harvest: `- { path: ^/, roles: ROLE_USER }`), which is right for
 * an internal ETL site but means every ADMIN_NAVBAR route — /storage, /workflows, /commands — 302s
 * to a login form on a machine that has no user rows. Granting PUBLIC_ACCESS in dev instead would
 * be worse for exactly these pages: they are admin UIs whose menus and buttons are wrapped in
 * is_granted(), so an anonymous request renders a stripped-down page that does not match what
 * production shows. Being logged in as a real admin is the point, not a side effect.
 *
 * OPT-IN, and deliberately so. zm has carried an app-local version of this since before this
 * bundle existed, and it is commented out with the reason: its persistent session made /login
 * redirect while the real login flow was being built. An authenticator that cannot be switched
 * off without editing security.yaml is one you end up fighting. This one is off unless
 * `survos_auth.dev_auto_login` names a user, and it steps aside for the auth routes themselves so
 * the real login flow stays reachable even while it is on.
 *
 * The service is only registered when configured AND the kernel is in debug mode; wire it into a
 * `when@dev` firewall block. It has no production code path.
 */
final class DevAutoLoginAuthenticator extends AbstractAuthenticator
{
    /**
     * Paths this must never claim. /login and /logout are the flow it would otherwise make
     * unreachable; the profiler and wdt are served inside the page being debugged, and
     * authenticating them produces a second, confusing login per request.
     */
    private const SKIP_PREFIXES = ['/login', '/logout', '/register', '/_wdt', '/_profiler', '/_fragment'];

    public function __construct(
        private readonly string $userIdentifier,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function supports(Request $request): ?bool
    {
        foreach (self::SKIP_PREFIXES as $prefix) {
            if (str_starts_with($request->getPathInfo(), $prefix)) {
                return false;
            }
        }

        // Already signed in — let the session token stand rather than re-authenticating on every
        // request, which would also stomp on switch_user and on a real login done by hand.
        if ($request->hasPreviousSession()) {
            try {
                foreach ($request->getSession()->all() as $key => $_) {
                    if (str_starts_with($key, '_security_')) {
                        return false;
                    }
                }
            } catch (\Throwable) {
                // A session that cannot be read is worse than no session: drop it and log in fresh.
                $request->getSession()->invalidate();
            }
        }

        return true;
    }

    public function authenticate(Request $request): Passport
    {
        return new SelfValidatingPassport(new UserBadge($this->userIdentifier));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        // Null continues the request. Redirecting would turn every first hit into a bounce, and
        // would lose POST bodies.
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        // The overwhelmingly likely cause is that the configured user does not exist in this
        // database — a fresh clone, or a dump without users. Say so plainly: the default
        // "Username could not be found." on a page nobody tried to log into is baffling.
        $this->logger?->error('Dev auto-login failed for "{user}" — does that user exist in this database?', [
            'user' => $this->userIdentifier,
            'exception' => $exception->getMessage(),
        ]);

        return null;
    }
}
