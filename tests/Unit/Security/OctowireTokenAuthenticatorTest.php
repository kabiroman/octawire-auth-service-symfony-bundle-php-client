<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Unit\Security;

use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;
use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireTokenAuthenticator;
use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireToken;
use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireUser;
use Kabiroman\Octawire\AuthService\Bundle\Service\TokenValidator;
use Kabiroman\Octawire\AuthService\Client\Model\TokenClaims;
use Kabiroman\Octawire\AuthService\Client\Response\JWT\ValidateTokenResponse;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

class OctowireTokenAuthenticatorTest extends TestCase
{
    private TokenValidator $tokenValidator;
    private AuthClientFactory $clientFactory;
    private OctowireTokenAuthenticator $authenticator;

    protected function setUp(): void
    {
        $this->tokenValidator = $this->createMock(TokenValidator::class);
        $this->clientFactory = $this->createMock(AuthClientFactory::class);
        $this->authenticator = new OctowireTokenAuthenticator(
            $this->tokenValidator,
            $this->clientFactory,
            'default-project'
        );
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

    public function testAuthenticateWithValidToken(): void
    {
        $token = 'valid.jwt.token';
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $tokenClaims = new TokenClaims(
            userId: 'user-123',
            tokenType: 'access',
            issuedAt: time(),
            expiresAt: time() + 3600,
            issuer: 'test-issuer',
            audience: 'test-audience',
            customClaims: ['role' => 'admin']
        );

        $validationResponse = new ValidateTokenResponse(
            valid: true,
            claims: $tokenClaims
        );

        $this->tokenValidator
            ->expects($this->once())
            ->method('extractProjectIdFromToken')
            ->with($token)
            ->willReturn(null);

        $this->clientFactory
            ->expects($this->never())
            ->method('hasProject');

        $this->tokenValidator
            ->expects($this->once())
            ->method('validateToken')
            ->with($token, 'default-project')
            ->willReturn($validationResponse);

        $passport = $this->authenticator->authenticate($request);

        $this->assertNotNull($passport);
        $user = $passport->getUser();
        $this->assertInstanceOf(OctowireUser::class, $user);
        $this->assertEquals('user-123', $user->getUserIdentifier());
    }

    public function testAuthenticateWithProjectIdFromToken(): void
    {
        $token = 'valid.jwt.token';
        $projectId = 'test-project';
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $tokenClaims = new TokenClaims(
            userId: 'user-123',
            tokenType: 'access',
            issuedAt: time(),
            expiresAt: time() + 3600,
            issuer: 'test-issuer',
            audience: 'test-audience'
        );

        $validationResponse = new ValidateTokenResponse(
            valid: true,
            claims: $tokenClaims
        );

        $this->tokenValidator
            ->expects($this->once())
            ->method('extractProjectIdFromToken')
            ->with($token)
            ->willReturn($projectId);

        $this->clientFactory
            ->expects($this->once())
            ->method('hasProject')
            ->with($projectId)
            ->willReturn(true);

        $this->tokenValidator
            ->expects($this->once())
            ->method('validateToken')
            ->with($token, $projectId)
            ->willReturn($validationResponse);

        $passport = $this->authenticator->authenticate($request);

        $this->assertNotNull($passport);
    }

    public function testAuthenticateThrowsExceptionWhenProjectIdNotInWhitelist(): void
    {
        $token = 'valid.jwt.token';
        $projectId = 'unauthorized-project';
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $this->tokenValidator
            ->expects($this->once())
            ->method('extractProjectIdFromToken')
            ->with($token)
            ->willReturn($projectId);

        $this->clientFactory
            ->expects($this->once())
            ->method('hasProject')
            ->with($projectId)
            ->willReturn(false);

        $this->clientFactory
            ->expects($this->once())
            ->method('getProjectIds')
            ->willReturn(['allowed-project-1', 'allowed-project-2']);

        $this->expectException(BadCredentialsException::class);
        $this->expectExceptionMessage('Token project ID "unauthorized-project" is not allowed on this service.');

        $this->authenticator->authenticate($request);
    }

    public function testAuthenticateThrowsExceptionWhenNoProjectIdAndNoDefault(): void
    {
        $token = 'valid.jwt.token';
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $token);

        // Create authenticator without default project
        $authenticator = new OctowireTokenAuthenticator(
            $this->tokenValidator,
            $this->clientFactory,
            null
        );

        $this->tokenValidator
            ->expects($this->once())
            ->method('extractProjectIdFromToken')
            ->with($token)
            ->willReturn(null);

        $this->expectException(BadCredentialsException::class);
        $this->expectExceptionMessage('Token does not contain project_id and no default_project is configured.');

        $authenticator->authenticate($request);
    }

    public function testAuthenticateThrowsExceptionWhenTokenInvalid(): void
    {
        $token = 'invalid.jwt.token';
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $validationResponse = new ValidateTokenResponse(
            valid: false,
            error: 'Token is invalid'
        );

        $this->tokenValidator
            ->expects($this->once())
            ->method('extractProjectIdFromToken')
            ->with($token)
            ->willReturn(null);

        $this->tokenValidator
            ->expects($this->once())
            ->method('validateToken')
            ->with($token, 'default-project')
            ->willReturn($validationResponse);

        $this->expectException(BadCredentialsException::class);
        $this->expectExceptionMessage('Token is invalid');

        $this->authenticator->authenticate($request);
    }

    public function testAuthenticateThrowsExceptionWhenClaimsMissing(): void
    {
        $token = 'valid.jwt.token';
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $validationResponse = new ValidateTokenResponse(
            valid: true,
            claims: null
        );

        $this->tokenValidator
            ->expects($this->once())
            ->method('extractProjectIdFromToken')
            ->with($token)
            ->willReturn(null);

        $this->tokenValidator
            ->expects($this->once())
            ->method('validateToken')
            ->with($token, 'default-project')
            ->willReturn($validationResponse);

        $this->expectException(BadCredentialsException::class);
        $this->expectExceptionMessage('Token claims not found.');

        $this->authenticator->authenticate($request);
    }
}




