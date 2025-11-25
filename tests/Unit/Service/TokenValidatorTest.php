<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Unit\Service;

use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;
use Kabiroman\Octawire\AuthService\Bundle\Service\TokenValidator;
use Kabiroman\Octawire\AuthService\Client\AuthClient;
use Kabiroman\Octawire\AuthService\Client\Exception\InvalidTokenException;
use Kabiroman\Octawire\AuthService\Client\Exception\TokenExpiredException;
use Kabiroman\Octawire\AuthService\Client\Exception\TokenRevokedException;
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
        $expectedResponse = [
            'valid' => true,
            'claims' => ['user_id' => 'user-123', 'role' => 'admin'],
        ];

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with(null)
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('validateToken')
            ->with([
                'token' => $token,
                'check_blacklist' => true,
                'jwt_token' => $token,
            ])
            ->willReturn($expectedResponse);

        $result = $this->tokenValidator->validateToken($token);

        $this->assertEquals($expectedResponse, $result);
    }

    public function testValidateTokenWithProjectId(): void
    {
        $token = 'valid.token';
        $projectId = 'test-project';
        $client = $this->createMock(AuthClient::class);

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with($projectId)
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('validateToken')
            ->willReturn(['valid' => true, 'claims' => []]);

        $this->tokenValidator->validateToken($token, $projectId);
    }

    public function testValidateTokenThrowsExceptionForInvalidToken(): void
    {
        $token = 'invalid.token';
        $client = $this->createMock(AuthClient::class);

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('validateToken')
            ->with([
                'token' => $token,
                'check_blacklist' => true,
                'jwt_token' => $token,
            ])
            ->willReturn(['valid' => false]);

        // When valid = false, BadCredentialsException is thrown directly
        // This happens before any catch blocks, so it should be the exception type
        try {
            $this->tokenValidator->validateToken($token);
            $this->fail('Expected BadCredentialsException was not thrown.');
        } catch (BadCredentialsException $e) {
            $this->assertEquals('Token is invalid.', $e->getMessage());
        } catch (\Exception $e) {
            $this->fail(sprintf(
                'Expected BadCredentialsException, got %s: %s',
                get_class($e),
                $e->getMessage()
            ));
        }
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
}




