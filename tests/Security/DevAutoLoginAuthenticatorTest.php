<?php

declare(strict_types=1);

namespace Survos\AuthBundle\Tests\Security;

use PHPUnit\Framework\TestCase;
use Survos\AuthBundle\Security\DevAutoLoginAuthenticator;
use Symfony\Component\HttpFoundation\Request;

/**
 * The authenticator is registered in every debug mode so a when@dev firewall can always name it;
 * only $enabled (a configured user AND kernel.debug) lets it act.
 */
final class DevAutoLoginAuthenticatorTest extends TestCase
{
    public function testADisabledAuthenticatorClaimsNoRequest(): void
    {
        self::assertFalse((new DevAutoLoginAuthenticator('', enabled: false))->supports(Request::create('/admin')));
    }

    public function testAnEnabledAuthenticatorClaimsAnOrdinaryPageButNotTheLoginFlow(): void
    {
        $authenticator = new DevAutoLoginAuthenticator('dev@example.com', enabled: true);

        self::assertTrue($authenticator->supports(Request::create('/admin')));
        self::assertFalse($authenticator->supports(Request::create('/login')));
    }
}
