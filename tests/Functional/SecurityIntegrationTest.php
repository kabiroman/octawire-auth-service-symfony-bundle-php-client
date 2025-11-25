<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Functional;

use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireTokenAuthenticator;
use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireUser;
use Kabiroman\Octawire\AuthService\Bundle\Service\TokenValidator;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * Functional tests for Security integration
 *
 * Note: These tests require a running Auth Service instance for full integration testing.
 * For now, they test the basic flow with mocked dependencies.
 */
class SecurityIntegrationTest extends TestCase
{
    public function testAuthenticatorSupportsBearerToken(): void
    {
        $tokenValidator = $this->createMock(TokenValidator::class);
        $authenticator = new OctowireTokenAuthenticator($tokenValidator, 'default-project');

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer test-token');

        $this->assertTrue($authenticator->supports($request));
    }

    public function testAuthenticatorRejectsRequestWithoutToken(): void
    {
        $tokenValidator = $this->createMock(TokenValidator::class);
        $authenticator = new OctowireTokenAuthenticator($tokenValidator, 'default-project');

        $request = new Request();

        $response = $authenticator->start($request);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertJson($response->getContent());
    }

    public function testUserCreationFromClaims(): void
    {
        $claims = [
            'user_id' => 'user-123',
            'sub' => 'user-123',
            'role' => 'admin',
            'custom_claim' => 'value',
        ];

        $user = OctowireUser::fromClaims($claims);

        $this->assertEquals('user-123', $user->getUserId());
        $this->assertEquals('user-123', $user->getUserIdentifier());
        $this->assertContains('ROLE_ADMIN', $user->getRoles());
        $this->assertContains('ROLE_USER', $user->getRoles());
        $this->assertEquals('value', $user->getClaim('custom_claim'));
    }
}




