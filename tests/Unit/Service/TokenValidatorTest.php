<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Unit\Service;

use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;
use Kabiroman\Octawire\AuthService\Bundle\Service\TokenValidator;
use Kabiroman\Octawire\AuthService\Client\AuthClient;
use Kabiroman\Octawire\AuthService\Client\Exception\InvalidTokenException;
use Kabiroman\Octawire\AuthService\Client\Exception\TokenExpiredException;
use Kabiroman\Octawire\AuthService\Client\Exception\TokenRevokedException;
use Kabiroman\Octawire\AuthService\Client\Model\TokenClaims;
use Kabiroman\Octawire\AuthService\Client\Request\JWT\ValidateTokenRequest;
use Kabiroman\Octawire\AuthService\Client\Response\JWT\ValidateTokenResponse;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

class TokenValidatorTest extends TestCase
{
    private AuthClientFactory $clientFactory;
    private TokenValidator $tokenValidator;

    protected function setUp(): void
    {
        $this->clientFactory = $this->createMock(AuthClientFactory::class);
        $this->tokenValidator = new TokenValidator($this->clientFactory);
    }

    public function testExtractProjectIdFromTokenReturnsNullForInvalidToken(): void
    {
        $result = $this->tokenValidator->extractProjectIdFromToken('invalid-token');
        $this->assertNull($result);
    }

    public function testExtractProjectIdFromTokenReturnsNullForEmptyToken(): void
    {
        $result = $this->tokenValidator->extractProjectIdFromToken('');
        $this->assertNull($result);
    }

    public function testExtractProjectIdFromValidToken(): void
    {
        // Create a valid JWT token structure (header.payload.signature)
        $payload = json_encode(['project_id' => 'test-project', 'user_id' => 'user-123']);
        $encodedPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        $token = 'header.' . $encodedPayload . '.signature';

        $result = $this->tokenValidator->extractProjectIdFromToken($token);

        $this->assertEquals('test-project', $result);
    }

    public function testExtractProjectIdFromTokenWithAudClaim(): void
    {
        $payload = json_encode(['aud' => 'test-project-aud', 'user_id' => 'user-123']);
        $encodedPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        $token = 'header.' . $encodedPayload . '.signature';

        $result = $this->tokenValidator->extractProjectIdFromToken($token);

        $this->assertEquals('test-project-aud', $result);
    }

    public function testValidateTokenSuccess(): void
    {
        $token = 'valid.token';
        $client = $this->createMock(AuthClient::class);
        
        $tokenClaims = new TokenClaims(
            userId: 'user-123',
            tokenType: 'access',
            issuedAt: time(),
            expiresAt: time() + 3600,
            issuer: 'test-issuer',
            audience: 'test-audience',
            customClaims: ['role' => 'admin']
        );
        
        $expectedResponse = new ValidateTokenResponse(
            valid: true,
            claims: $tokenClaims
        );

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with(null)
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('validateToken')
            ->with(
                $this->isInstanceOf(ValidateTokenRequest::class),
                $token
            )
            ->willReturn($expectedResponse);

        $result = $this->tokenValidator->validateToken($token);

        $this->assertInstanceOf(ValidateTokenResponse::class, $result);
        $this->assertTrue($result->valid);
        $this->assertNotNull($result->claims);
        $this->assertEquals('user-123', $result->claims->userId);
    }

    public function testValidateTokenWithProjectId(): void
    {
        $token = 'valid.token';
        $projectId = 'test-project';
        $client = $this->createMock(AuthClient::class);
        
        $tokenClaims = new TokenClaims(
            userId: 'user-123',
            tokenType: 'access',
            issuedAt: time(),
            expiresAt: time() + 3600,
            issuer: 'test-issuer',
            audience: 'test-audience'
        );
        
        $expectedResponse = new ValidateTokenResponse(
            valid: true,
            claims: $tokenClaims
        );

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with($projectId)
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('validateToken')
            ->with(
                $this->isInstanceOf(ValidateTokenRequest::class),
                $token
            )
            ->willReturn($expectedResponse);

        $result = $this->tokenValidator->validateToken($token, $projectId);
        
        $this->assertInstanceOf(ValidateTokenResponse::class, $result);
        $this->assertTrue($result->valid);
    }

    public function testValidateTokenThrowsExceptionForInvalidToken(): void
    {
        $token = 'invalid.token';
        $client = $this->createMock(AuthClient::class);
        
        $expectedResponse = new ValidateTokenResponse(
            valid: false,
            error: 'Token is invalid'
        );

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('validateToken')
            ->with(
                $this->isInstanceOf(ValidateTokenRequest::class),
                $token
            )
            ->willReturn($expectedResponse);

        // When valid = false, BadCredentialsException is thrown directly
        $this->expectException(BadCredentialsException::class);
        $this->expectExceptionMessage('Token is invalid');

        $this->tokenValidator->validateToken($token);
    }

    public function testValidateTokenHandlesTokenExpiredException(): void
    {
        $token = 'expired.token';
        $client = $this->createMock(AuthClient::class);

        $this->clientFactory
            ->method('getClient')
            ->willReturn($client);

        $client
            ->method('validateToken')
            ->willThrowException(new TokenExpiredException('Token expired'));

        $this->expectException(BadCredentialsException::class);
        $this->expectExceptionMessage('Token has expired.');

        $this->tokenValidator->validateToken($token);
    }

    public function testValidateTokenHandlesTokenRevokedException(): void
    {
        $token = 'revoked.token';
        $client = $this->createMock(AuthClient::class);

        $this->clientFactory
            ->method('getClient')
            ->willReturn($client);

        $client
            ->method('validateToken')
            ->willThrowException(new TokenRevokedException('Token revoked'));

        $this->expectException(BadCredentialsException::class);
        $this->expectExceptionMessage('Token has been revoked.');

        $this->tokenValidator->validateToken($token);
    }

    public function testValidateTokenHandlesInvalidTokenException(): void
    {
        $token = 'invalid.token';
        $client = $this->createMock(AuthClient::class);

        $this->clientFactory
            ->method('getClient')
            ->willReturn($client);

        $client
            ->method('validateToken')
            ->willThrowException(new InvalidTokenException('Invalid token'));

        $this->expectException(BadCredentialsException::class);
        $this->expectExceptionMessage('Token is invalid.');

        $this->tokenValidator->validateToken($token);
    }

    public function testValidateTokenHandlesGenericException(): void
    {
        $token = 'error.token';
        $client = $this->createMock(AuthClient::class);

        $this->clientFactory
            ->method('getClient')
            ->willReturn($client);

        $client
            ->method('validateToken')
            ->willThrowException(new \RuntimeException('Connection error'));

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Token validation failed.');

        $this->tokenValidator->validateToken($token);
    }

    public function testValidateTokenWithLocalMode(): void
    {
        $token = 'valid.token';
        $localValidator = $this->createMock(\Kabiroman\Octawire\AuthService\Bundle\Service\LocalTokenValidator::class);
        
        $tokenClaims = new \Kabiroman\Octawire\AuthService\Client\Model\TokenClaims(
            userId: 'user-123',
            tokenType: 'access',
            issuedAt: time(),
            expiresAt: time() + 3600,
            issuer: 'test-issuer',
            audience: 'test-audience'
        );
        
        $expectedResponse = new \Kabiroman\Octawire\AuthService\Client\Response\JWT\ValidateTokenResponse(
            valid: true,
            claims: $tokenClaims
        );

        $localValidator
            ->expects($this->once())
            ->method('validateToken')
            ->with($token, null)
            ->willReturn($expectedResponse);

        $validator = new TokenValidator($this->clientFactory, 'local', true, $localValidator);
        $result = $validator->validateToken($token);

        $this->assertInstanceOf(\Kabiroman\Octawire\AuthService\Client\Response\JWT\ValidateTokenResponse::class, $result);
        $this->assertTrue($result->valid);
    }

    public function testValidateTokenWithHybridMode(): void
    {
        $token = 'valid.token';
        $localValidator = $this->createMock(\Kabiroman\Octawire\AuthService\Bundle\Service\LocalTokenValidator::class);
        $client = $this->createMock(\Kabiroman\Octawire\AuthService\Client\AuthClient::class);
        
        $tokenClaims = new \Kabiroman\Octawire\AuthService\Client\Model\TokenClaims(
            userId: 'user-123',
            tokenType: 'access',
            issuedAt: time(),
            expiresAt: time() + 3600,
            issuer: 'test-issuer',
            audience: 'test-audience'
        );
        
        $localResponse = new \Kabiroman\Octawire\AuthService\Client\Response\JWT\ValidateTokenResponse(
            valid: true,
            claims: $tokenClaims
        );
        
        $blacklistResponse = new \Kabiroman\Octawire\AuthService\Client\Response\JWT\ValidateTokenResponse(
            valid: true,
            claims: $tokenClaims
        );

        $localValidator
            ->expects($this->once())
            ->method('validateToken')
            ->with($token, null)
            ->willReturn($localResponse);

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with(null)
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('validateToken')
            ->with(
                $this->isInstanceOf(\Kabiroman\Octawire\AuthService\Client\Request\JWT\ValidateTokenRequest::class),
                $token
            )
            ->willReturn($blacklistResponse);

        $validator = new TokenValidator($this->clientFactory, 'hybrid', true, $localValidator);
        $result = $validator->validateToken($token);

        $this->assertInstanceOf(\Kabiroman\Octawire\AuthService\Client\Response\JWT\ValidateTokenResponse::class, $result);
        $this->assertTrue($result->valid);
    }

    public function testValidateTokenWithHybridModeSkipsBlacklistWhenCheckBlacklistFalse(): void
    {
        $token = 'valid.token';
        $localValidator = $this->createMock(\Kabiroman\Octawire\AuthService\Bundle\Service\LocalTokenValidator::class);
        
        $tokenClaims = new \Kabiroman\Octawire\AuthService\Client\Model\TokenClaims(
            userId: 'user-123',
            tokenType: 'access',
            issuedAt: time(),
            expiresAt: time() + 3600,
            issuer: 'test-issuer',
            audience: 'test-audience'
        );
        
        $localResponse = new \Kabiroman\Octawire\AuthService\Client\Response\JWT\ValidateTokenResponse(
            valid: true,
            claims: $tokenClaims
        );

        $localValidator
            ->expects($this->once())
            ->method('validateToken')
            ->with($token, null)
            ->willReturn($localResponse);

        $this->clientFactory
            ->expects($this->never())
            ->method('getClient');

        $validator = new TokenValidator($this->clientFactory, 'hybrid', false, $localValidator);
        $result = $validator->validateToken($token);

        $this->assertInstanceOf(\Kabiroman\Octawire\AuthService\Client\Response\JWT\ValidateTokenResponse::class, $result);
        $this->assertTrue($result->valid);
    }

    public function testValidateTokenThrowsExceptionWhenLocalValidatorMissing(): void
    {
        $token = 'valid.token';
        $validator = new TokenValidator($this->clientFactory, 'local', true, null);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('LocalTokenValidator is required for local validation mode.');

        $validator->validateToken($token);
    }
}




