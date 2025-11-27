<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Unit\Service;

use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;
use Kabiroman\Octawire\AuthService\Bundle\Service\ServiceAuthProvider;
use Kabiroman\Octawire\AuthService\Bundle\Service\TokenValidator;
use Kabiroman\Octawire\AuthService\Client\AuthClient;
use Kabiroman\Octawire\AuthService\Client\Exception\AuthException;
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
        $projectId = 'test-project';
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

        $serviceAuthProvider = new ServiceAuthProvider([
            $projectId => [
                'service_name' => 'symfony-app',
                'service_secret' => 'secret',
            ],
        ]);

        $this->clientFactory
            ->expects($this->exactly(2))
            ->method('getClient')
            ->with($projectId)
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
            $serviceAuthProvider
        );

        $validator->validateToken($token, $projectId);
        $validator->validateToken($token, $projectId);
    }

    public function testValidateTokenSkipsServiceTokenWhenNotConfigured(): void
    {
        $token = 'valid.token';
        $client = $this->createMock(AuthClient::class);
        $expectedResponse = new ValidateTokenResponse(valid: true, claims: $this->createTokenClaims());

        $serviceAuthProvider = new ServiceAuthProvider([]); // Empty provider

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

        $validator = new TokenValidator($this->clientFactory, 'remote', true, null, $serviceAuthProvider);
        $validator->validateToken($token);
    }

    public function testValidateTokenThrowsWhenServiceNotAllowed(): void
    {
        $token = 'valid.token';
        $projectId = 'test-project';
        $client = $this->createMock(AuthClient::class);

        $serviceAuthProvider = new ServiceAuthProvider([
            $projectId => [
                'service_name' => 'symfony-app',
                'service_secret' => 'secret',
            ],
        ]);

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with($projectId)
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('issueServiceToken')
            ->willThrowException(new \RuntimeException('service not allowed'));

        $client
            ->expects($this->never())
            ->method('validateToken');

        $validator = new TokenValidator($this->clientFactory, 'remote', true, null, $serviceAuthProvider);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Service authentication failed: service not allowed');

        $validator->validateToken($token, $projectId);
    }

    public function testValidateTokenThrowsWhenServiceTokenExpired(): void
    {
        $token = 'valid.token';
        $projectId = 'test-project';
        $client = $this->createMock(AuthClient::class);
        $expiredServiceToken = $this->createJwtToken(['exp' => time() - 10]);
        $nextServiceToken = $this->createJwtToken(['exp' => time() + 3600]);
        $expectedResponse = new ValidateTokenResponse(valid: true, claims: $this->createTokenClaims());

        $serviceAuthProvider = new ServiceAuthProvider([
            $projectId => [
                'service_name' => 'symfony-app',
                'service_secret' => 'secret',
            ],
        ]);

        $this->clientFactory
            ->expects($this->exactly(2))
            ->method('getClient')
            ->with($projectId)
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

        $validator = new TokenValidator($this->clientFactory, 'remote', true, null, $serviceAuthProvider);
        $validator->validateToken($token, $projectId);
        $validator->validateToken($token, $projectId);
    }


    public function testValidateTokenReissuesServiceTokenWhenExpiringSoon(): void
    {
        $token = 'valid.token';
        $projectId = 'test-project';
        $client = $this->createMock(AuthClient::class);
        $claims = $this->createTokenClaims();
        $expectedResponse = new ValidateTokenResponse(valid: true, claims: $claims);
        $soonExpiringToken = $this->createJwtToken(['exp' => time() + 30]);
        $newToken = $this->createJwtToken(['exp' => time() + 3600]);

        $serviceAuthProvider = new ServiceAuthProvider([
            $projectId => [
                'service_name' => 'symfony-app',
                'service_secret' => 'secret',
            ],
        ]);

        $this->clientFactory
            ->expects($this->exactly(2))
            ->method('getClient')
            ->with($projectId)
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
            $serviceAuthProvider
        );

        $validator->validateToken($token, $projectId);
        $validator->validateToken($token, $projectId);
    }

    public function testValidateTokenThrowsWhenServiceTokenIssuanceFails(): void
    {
        $token = 'valid.token';
        $projectId = 'test-project';
        $client = $this->createMock(AuthClient::class);

        $serviceAuthProvider = new ServiceAuthProvider([
            $projectId => [
                'service_name' => 'symfony-app',
                'service_secret' => 'secret',
            ],
        ]);

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with($projectId)
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('issueServiceToken')
            ->with($this->isInstanceOf(IssueServiceTokenRequest::class), 'secret')
            ->willThrowException(new \RuntimeException('service auth failed'));

        $client
            ->expects($this->never())
            ->method('validateToken');

        $validator = new TokenValidator(
            $this->clientFactory,
            'remote',
            true,
            null,
            $serviceAuthProvider
        );

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Service authentication failed: service auth failed');

        $validator->validateToken($token, $projectId);
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

    public function testValidateTokenHandlesAUTH_FAILEDException(): void
    {
        $token = 'valid.token';
        $projectId = 'test-project';
        $client = $this->createMock(AuthClient::class);

        $serviceAuthProvider = new ServiceAuthProvider([
            $projectId => [
                'service_name' => 'symfony-app',
                'service_secret' => 'invalid-secret',
            ],
        ]);

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with($projectId)
            ->willReturn($client);

        $authException = new AuthException(
            'Invalid service credentials',
            403,
            null,
            'AUTH_FAILED',
            []
        );

        $client
            ->expects($this->once())
            ->method('issueServiceToken')
            ->willThrowException($authException);

        $validator = new TokenValidator(
            $this->clientFactory,
            'remote',
            true,
            null,
            $serviceAuthProvider
        );

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Service authentication failed: Invalid service credentials. Check service_name and service_secret configuration for project ' . $projectId . '.');

        $validator->validateToken($token, $projectId);
    }

    public function testValidateTokenWithPerProjectServiceAuth(): void
    {
        $token = 'valid.token';
        $project1Id = 'project-1';
        $project2Id = 'project-2';
        $client1 = $this->createMock(AuthClient::class);
        $client2 = $this->createMock(AuthClient::class);
        
        $serviceToken1 = $this->createJwtToken(['exp' => time() + 3600]);
        $serviceToken2 = $this->createJwtToken(['exp' => time() + 3600]);
        $claims = $this->createTokenClaims();
        $expectedResponse = new ValidateTokenResponse(valid: true, claims: $claims);

        $serviceAuthProvider = new ServiceAuthProvider([
            $project1Id => [
                'service_name' => 'api-gateway',
                'service_secret' => 'secret-1',
            ],
            $project2Id => [
                'service_name' => 'internal-api',
                'service_secret' => 'secret-2',
            ],
        ]);

        // First project
        $this->clientFactory
            ->expects($this->exactly(2))
            ->method('getClient')
            ->willReturnCallback(function ($projectId) use ($project1Id, $project2Id, $client1, $client2) {
                if ($projectId === $project1Id) {
                    return $client1;
                }
                if ($projectId === $project2Id) {
                    return $client2;
                }
                return $client1;
            });

        $client1
            ->expects($this->once())
            ->method('issueServiceToken')
            ->with(
                $this->callback(function ($request) use ($project1Id) {
                    return $request instanceof IssueServiceTokenRequest
                        && $request->sourceService === 'api-gateway'
                        && $request->projectId === $project1Id;
                }),
                'secret-1'
            )
            ->willReturn(new IssueTokenResponse($serviceToken1, 'refresh', time() + 3600, time() + 7200, 'key-1'));

        $client1
            ->expects($this->once())
            ->method('validateToken')
            ->with($this->isInstanceOf(ValidateTokenRequest::class), $serviceToken1)
            ->willReturn($expectedResponse);

        // Second project
        $client2
            ->expects($this->once())
            ->method('issueServiceToken')
            ->with(
                $this->callback(function ($request) use ($project2Id) {
                    return $request instanceof IssueServiceTokenRequest
                        && $request->sourceService === 'internal-api'
                        && $request->projectId === $project2Id;
                }),
                'secret-2'
            )
            ->willReturn(new IssueTokenResponse($serviceToken2, 'refresh', time() + 3600, time() + 7200, 'key-1'));

        $client2
            ->expects($this->once())
            ->method('validateToken')
            ->with($this->isInstanceOf(ValidateTokenRequest::class), $serviceToken2)
            ->willReturn($expectedResponse);

        $validator = new TokenValidator(
            $this->clientFactory,
            'remote',
            true,
            null,
            $serviceAuthProvider
        );

        // Validate with first project
        $result1 = $validator->validateToken($token, $project1Id);
        $this->assertTrue($result1->valid);

        // Validate with second project
        $result2 = $validator->validateToken($token, $project2Id);
        $this->assertTrue($result2->valid);
    }

    public function testValidateTokenReturnsNullServiceTokenWhenProjectIdIsNull(): void
    {
        $token = 'valid.token';
        $client = $this->createMock(AuthClient::class);
        $expectedResponse = new ValidateTokenResponse(valid: true, claims: $this->createTokenClaims());

        $serviceAuthProvider = new ServiceAuthProvider([
            'test-project' => [
                'service_name' => 'symfony-app',
                'service_secret' => 'secret',
            ],
        ]);

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with(null)
            ->willReturn($client);

        // Should not call issueServiceToken when projectId is null
        $client
            ->expects($this->never())
            ->method('issueServiceToken');

        $client
            ->expects($this->once())
            ->method('validateToken')
            ->with($this->isInstanceOf(ValidateTokenRequest::class), null)
            ->willReturn($expectedResponse);

        $validator = new TokenValidator(
            $this->clientFactory,
            'remote',
            true,
            null,
            $serviceAuthProvider
        );

        $result = $validator->validateToken($token, null);
        $this->assertTrue($result->valid);
    }

    public function testValidateTokenUsesCachedServiceTokenPerProject(): void
    {
        $token = 'valid.token';
        $project1Id = 'project-1';
        $project2Id = 'project-2';
        $client = $this->createMock(AuthClient::class);
        
        $serviceToken1 = $this->createJwtToken(['exp' => time() + 3600]);
        $serviceToken2 = $this->createJwtToken(['exp' => time() + 3600]);
        $claims = $this->createTokenClaims();
        $expectedResponse = new ValidateTokenResponse(valid: true, claims: $claims);

        $serviceAuthProvider = new ServiceAuthProvider([
            $project1Id => [
                'service_name' => 'api-gateway',
                'service_secret' => 'secret-1',
            ],
            $project2Id => [
                'service_name' => 'internal-api',
                'service_secret' => 'secret-2',
            ],
        ]);

        $this->clientFactory
            ->expects($this->exactly(4))
            ->method('getClient')
            ->willReturn($client);

        // Each project should issue service token only once (cached for second call)
        $client
            ->expects($this->exactly(2))
            ->method('issueServiceToken')
            ->willReturnCallback(function ($request, $secret) use ($project1Id, $project2Id, $serviceToken1, $serviceToken2) {
                if ($request->projectId === $project1Id && $secret === 'secret-1') {
                    return new IssueTokenResponse($serviceToken1, 'refresh', time() + 3600, time() + 7200, 'key-1');
                }
                if ($request->projectId === $project2Id && $secret === 'secret-2') {
                    return new IssueTokenResponse($serviceToken2, 'refresh', time() + 3600, time() + 7200, 'key-1');
                }
                throw new \RuntimeException('Unexpected call');
            });

        // Each project should validate twice (using cached tokens)
        $client
            ->expects($this->exactly(4))
            ->method('validateToken')
            ->willReturnCallback(function ($request, $jwtToken) use ($serviceToken1, $serviceToken2, $expectedResponse) {
                if ($jwtToken === $serviceToken1 || $jwtToken === $serviceToken2) {
                    return $expectedResponse;
                }
                return $expectedResponse;
            });

        $validator = new TokenValidator(
            $this->clientFactory,
            'remote',
            true,
            null,
            $serviceAuthProvider
        );

        // Validate with project 1 twice (should cache)
        $validator->validateToken($token, $project1Id);
        $validator->validateToken($token, $project1Id);

        // Validate with project 2 twice (should cache separately)
        $validator->validateToken($token, $project2Id);
        $validator->validateToken($token, $project2Id);
    }

    public function testValidateTokenHandlesAuthExceptionWithNonAUTH_FAILEDCode(): void
    {
        $token = 'valid.token';
        $projectId = 'test-project';
        $client = $this->createMock(AuthClient::class);

        $serviceAuthProvider = new ServiceAuthProvider([
            $projectId => [
                'service_name' => 'symfony-app',
                'service_secret' => 'secret',
            ],
        ]);

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with($projectId)
            ->willReturn($client);

        $authException = new AuthException(
            'Some other auth error',
            500,
            null,
            'ERROR_INTERNAL',
            []
        );

        $client
            ->expects($this->once())
            ->method('issueServiceToken')
            ->willThrowException($authException);

        $validator = new TokenValidator(
            $this->clientFactory,
            'remote',
            true,
            null,
            $serviceAuthProvider
        );

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Service authentication failed: Some other auth error');

        $validator->validateToken($token, $projectId);
    }

    public function testValidateTokenWithHybridModeUsesServiceTokenForBlacklistCheck(): void
    {
        $token = 'valid.token';
        $projectId = 'test-project';
        $localValidator = $this->createMock(\Kabiroman\Octawire\AuthService\Bundle\Service\LocalTokenValidator::class);
        $client = $this->createMock(AuthClient::class);
        
        $tokenClaims = $this->createTokenClaims();
        $localResponse = new ValidateTokenResponse(valid: true, claims: $tokenClaims);
        $blacklistResponse = new ValidateTokenResponse(valid: true, claims: $tokenClaims);
        $serviceToken = $this->createJwtToken(['exp' => time() + 3600]);

        $serviceAuthProvider = new ServiceAuthProvider([
            $projectId => [
                'service_name' => 'symfony-app',
                'service_secret' => 'secret',
            ],
        ]);

        $localValidator
            ->expects($this->once())
            ->method('validateToken')
            ->with($token, $projectId)
            ->willReturn($localResponse);

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with($projectId)
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('issueServiceToken')
            ->willReturn(new IssueTokenResponse($serviceToken, 'refresh', time() + 3600, time() + 7200, 'key-1'));

        $client
            ->expects($this->once())
            ->method('validateToken')
            ->with(
                $this->isInstanceOf(ValidateTokenRequest::class),
                $serviceToken
            )
            ->willReturn($blacklistResponse);

        $validator = new TokenValidator(
            $this->clientFactory,
            'hybrid',
            true,
            $localValidator,
            $serviceAuthProvider
        );

        $result = $validator->validateToken($token, $projectId);
        $this->assertTrue($result->valid);
    }

    public function testValidateTokenSkipsServiceTokenWhenProjectIdNotInProvider(): void
    {
        $token = 'valid.token';
        $projectId = 'non-configured-project';
        $client = $this->createMock(AuthClient::class);
        $expectedResponse = new ValidateTokenResponse(valid: true, claims: $this->createTokenClaims());

        $serviceAuthProvider = new ServiceAuthProvider([
            'other-project' => [
                'service_name' => 'other-service',
                'service_secret' => 'other-secret',
            ],
        ]);

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with($projectId)
            ->willReturn($client);

        // Should not call issueServiceToken when project is not in provider
        $client
            ->expects($this->never())
            ->method('issueServiceToken');

        $client
            ->expects($this->once())
            ->method('validateToken')
            ->with($this->isInstanceOf(ValidateTokenRequest::class), null)
            ->willReturn($expectedResponse);

        $validator = new TokenValidator(
            $this->clientFactory,
            'remote',
            true,
            null,
            $serviceAuthProvider
        );

        $result = $validator->validateToken($token, $projectId);
        $this->assertTrue($result->valid);
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




