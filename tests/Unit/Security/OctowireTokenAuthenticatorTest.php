<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Unit\Security;

use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireTokenAuthenticator;
use Kabiroman\Octawire\AuthService\Bundle\Service\TokenValidator;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

class OctowireTokenAuthenticatorTest extends TestCase
{
    private TokenValidator $tokenValidator;
    private OctowireTokenAuthenticator $authenticator;

    protected function setUp(): void
    {
        $this->tokenValidator = $this->createMock(TokenValidator::class);
        $this->authenticator = new OctowireTokenAuthenticator($this->tokenValidator, 'default-project');
    }

    public function testSupportsReturnsTrueWhenAuthorizationHeaderPresent(): void
    {
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer test-token');

        $this->assertTrue($this->authenticator->supports($request));
    }

    public function testSupportsReturnsFalseWhenAuthorizationHeaderMissing(): void
    {
        $request = new Request();

        $this->assertFalse($this->authenticator->supports($request));
    }

    public function testSupportsReturnsFalseWhenAuthorizationHeaderNotBearer(): void
    {
        $request = new Request();
        $request->headers->set('Authorization', 'Basic test');

        $this->assertFalse($this->authenticator->supports($request));
    }

    public function testStartReturns401Response(): void
    {
        $request = new Request();
        $response = $this->authenticator->start($request);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertJson($response->getContent());
        
        $content = json_decode($response->getContent(), true);
        $this->assertEquals('Authentication required', $content['error']);
    }

    public function testOnAuthenticationFailureReturns401Response(): void
    {
        $request = new Request();
        $exception = new \Symfony\Component\Security\Core\Exception\BadCredentialsException('Invalid token');

        $response = $this->authenticator->onAuthenticationFailure($request, $exception);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertJson($response->getContent());
        
        $content = json_decode($response->getContent(), true);
        $this->assertEquals('Authentication failed', $content['error']);
        $this->assertEquals('Invalid token', $content['message']);
    }

    public function testOnAuthenticationSuccessReturnsNull(): void
    {
        $request = new Request();
        $token = $this->createMock(\Symfony\Component\Security\Core\Authentication\Token\TokenInterface::class);

        $response = $this->authenticator->onAuthenticationSuccess($request, $token, 'test');

        $this->assertNull($response);
    }
}




