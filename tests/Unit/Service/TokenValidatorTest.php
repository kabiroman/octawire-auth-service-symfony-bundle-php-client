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
use Kabiroman\Octawire\AuthService\Client\Request\JWT\IssueServiceTokenRequest;
use Kabiroman\Octawire\AuthService\Client\Request\JWT\ValidateTokenRequest;
use Kabiroman\Octawire\AuthService\Client\Response\JWT\IssueTokenResponse;
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
                $this->anything()
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
                $this->anything()
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
                $this->anything()
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
        $this->expectExceptionMessage('Token validation failed: Connection error');

        $this->tokenValidator->validateToken($token);
    }

    public function testValidateTokenUsesServiceTokenCache(): void
    {
        $token = 'valid.token';
        $client = $this->createMock(AuthClient::class);
        $serviceToken = $this->createJwtToken(['exp' => time() + 3600]);
        $claims = $this->createTokenClaims();
        $expectedResponse = new ValidateTokenResponse(valid: true, claims: $claims);
        $serviceTokenResponse = new IssueTokenResponse(
            accessToken: $serviceToken,
            refreshToken: 'refresh',
            accessTokenExpiresAt: time() + 3600,
            refreshTokenExpiresAt: time() + 7200,
            keyId: 'key-1'
        );

        $this->clientFactory
            ->expects($this->exactly(2))
            ->method('getClient')
            ->with(null)
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('issueServiceToken')
            ->with($this->isInstanceOf(IssueServiceTokenRequest::class), 'secret')
            ->willReturn($serviceTokenResponse);

        $client
            ->expects($this->exactly(2))
            ->method('validateToken')
            ->with(
                $this->isInstanceOf(ValidateTokenRequest::class),
                $serviceToken
            )
            ->willReturn($expectedResponse);

        $validator = new TokenValidator(
            $this->clientFactory,
            'remote',
            true,
            null,
            'symfony-app',
            'secret'
        );

        $validator->validateToken($token);
        $validator->validateToken($token);
    }

    public function testValidateTokenSkipsServiceTokenWhenNotConfigured(): void
    {
        $token = 'valid.token';
        $client = $this->createMock(AuthClient::class);
        $expectedResponse = new ValidateTokenResponse(valid: true, claims: $this->createTokenClaims());

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with(null)
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('validateToken')
            ->with($this->isInstanceOf(ValidateTokenRequest::class), null)
            ->willReturn($expectedResponse);

        $validator = new TokenValidator($this->clientFactory, 'remote', true, null, null, null);
        $validator->validateToken($token);
    }

    public function testValidateTokenThrowsWhenServiceNotAllowed(): void
    {
        $token = 'valid.token';
        $client = $this->createMock(AuthClient::class);

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with(null)
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('issueServiceToken')
            ->willThrowException(new \RuntimeException('service not allowed'));

        $client
            ->expects($this->once())
            ->method('validateToken')
            ->with($this->isInstanceOf(ValidateTokenRequest::class), null)
            ->willReturn(new ValidateTokenResponse(valid: true, claims: $this->createTokenClaims()));

        $validator = new TokenValidator($this->clientFactory, 'remote', true, null, 'symfony-app', 'secret');
        $validator->validateToken($token);
    }

    public function testValidateTokenThrowsWhenServiceTokenExpired(): void
    {
        $token = 'valid.token';
        $client = $this->createMock(AuthClient::class);
        $expiredServiceToken = $this->createJwtToken(['exp' => time() - 10]);
        $nextServiceToken = $this->createJwtToken(['exp' => time() + 3600]);
        $expectedResponse = new ValidateTokenResponse(valid: true, claims: $this->createTokenClaims());

        $this->clientFactory
            ->expects($this->exactly(2))
            ->method('getClient')
            ->with(null)
            ->willReturn($client);

        $client
            ->expects($this->exactly(2))
            ->method('issueServiceToken')
            ->willReturnOnConsecutiveCalls(
                new IssueTokenResponse($expiredServiceToken, 'refresh', time() - 10, time() + 100, 'key-1'),
                new IssueTokenResponse($nextServiceToken, 'refresh', time() + 3600, time() + 7200, 'key-1')
            );

        $expectedTokens = [$expiredServiceToken, $nextServiceToken];

        $client
            ->expects($this->exactly(2))
            ->method('validateToken')
            ->willReturnCallback(function ($request, $jwtToken) use (&$expectedTokens, $expectedResponse) {
                $this->assertInstanceOf(ValidateTokenRequest::class, $request);
                $this->assertSame(array_shift($expectedTokens), $jwtToken);
                return $expectedResponse;
            });

        $validator = new TokenValidator($this->clientFactory, 'remote', true, null, 'symfony-app', 'secret');
        $validator->validateToken($token);
        $validator->validateToken($token);
    }


    public function testValidateTokenReissuesServiceTokenWhenExpiringSoon(): void
    {
        $token = 'valid.token';
        $client = $this->createMock(AuthClient::class);
        $claims = $this->createTokenClaims();
        $expectedResponse = new ValidateTokenResponse(valid: true, claims: $claims);
        $soonExpiringToken = $this->createJwtToken(['exp' => time() + 30]);
        $newToken = $this->createJwtToken(['exp' => time() + 3600]);

        $this->clientFactory
            ->expects($this->exactly(2))
            ->method('getClient')
            ->with(null)
            ->willReturn($client);

        $client
            ->expects($this->exactly(2))
            ->method('issueServiceToken')
            ->with($this->isInstanceOf(IssueServiceTokenRequest::class), 'secret')
            ->willReturnOnConsecutiveCalls(
                new IssueTokenResponse($soonExpiringToken, 'refresh', time() + 30, time() + 60, 'key-1'),
                new IssueTokenResponse($newToken, 'refresh', time() + 3600, time() + 7200, 'key-1')
            );

        $expectedTokens = [$soonExpiringToken, $newToken];

        $client
            ->expects($this->exactly(2))
            ->method('validateToken')
            ->willReturnCallback(function ($request, $jwtToken) use (&$expectedTokens, $expectedResponse) {
                $this->assertInstanceOf(ValidateTokenRequest::class, $request);
                $this->assertSame(array_shift($expectedTokens), $jwtToken);
                return $expectedResponse;
            });

        $validator = new TokenValidator(
            $this->clientFactory,
            'remote',
            true,
            null,
            'symfony-app',
            'secret'
        );

        $validator->validateToken($token);
        $validator->validateToken($token);
    }

    public function testValidateTokenFallsBackWhenServiceTokenIssuanceFails(): void
    {
        $token = 'valid.token';
        $client = $this->createMock(AuthClient::class);
        $claims = $this->createTokenClaims();
        $expectedResponse = new ValidateTokenResponse(valid: true, claims: $claims);

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with(null)
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('issueServiceToken')
            ->with($this->isInstanceOf(IssueServiceTokenRequest::class), 'secret')
            ->willThrowException(new \RuntimeException('service auth failed'));

        $client
            ->expects($this->once())
            ->method('validateToken')
            ->with(
                $this->isInstanceOf(ValidateTokenRequest::class),
                null
            )
            ->willReturn($expectedResponse);

        $validator = new TokenValidator(
            $this->clientFactory,
            'remote',
            true,
            null,
            'symfony-app',
            'secret'
        );

        $validator->validateToken($token);
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
                $this->anything()
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

    private function createTokenClaims(): TokenClaims
    {
        return new TokenClaims(
            userId: 'user-123',
            tokenType: 'access',
            issuedAt: time(),
            expiresAt: time() + 3600,
            issuer: 'test-issuer',
            audience: 'test-audience',
            customClaims: ['role' => 'user']
        );
    }

    private function createJwtToken(array $payload): string
    {
        $header = $this->encodeSegment(['alg' => 'RS256', 'typ' => 'JWT']);
        $payloadSegment = $this->encodeSegment($payload);

        return $header . '.' . $payloadSegment . '.signature';
    }

    private function encodeSegment(array $data): string
    {
        return rtrim(strtr(base64_encode(json_encode($data, JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
    }
}




