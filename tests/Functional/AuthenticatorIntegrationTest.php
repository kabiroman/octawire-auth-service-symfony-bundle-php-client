<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Functional;

use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireUser;
use Kabiroman\Octawire\AuthService\Client\AuthClient;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Integration tests for Authenticator with Symfony Security
 *
 * These tests require proper mocking of AuthClient to avoid network calls.
 */
class AuthenticatorIntegrationTest extends KernelTestCase
{
    private AuthClient $mockClient;

    protected function setUp(): void
    {
        parent::setUp();
        self::bootKernel();

        // Get the client and mock it
        $container = self::getContainer();
        $factory = $container->get('octawire_auth.client_factory');
        $this->mockClient = $factory->getClient('test-project');
    }

    public function testAuthenticatorSupportsBearerToken(): void
    {
        $container = self::getContainer();
        $authenticator = $container->get('octawire_auth.authenticator');

        $request = Request::create('/test', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer test-token'
        ]);

        $this->assertTrue($authenticator->supports($request));
    }

    public function testAuthenticatorRejectsRequestWithoutToken(): void
    {
        $container = self::getContainer();
        $authenticator = $container->get('octawire_auth.authenticator');

        $request = Request::create('/test', 'GET');

        $this->assertFalse($authenticator->supports($request));
    }

    public function testStartMethodReturns401Response(): void
    {
        $container = self::getContainer();
        $authenticator = $container->get('octawire_auth.authenticator');

        $request = Request::create('/test', 'GET');
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

