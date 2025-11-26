<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Unit\Service;

use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;
use Kabiroman\Octawire\AuthService\Bundle\Service\LocalTokenValidator;
use Kabiroman\Octawire\AuthService\Client\AuthClient;
use Kabiroman\Octawire\AuthService\Client\Model\PublicKeyInfo;
use Kabiroman\Octawire\AuthService\Client\Request\JWT\GetPublicKeyRequest;
use Kabiroman\Octawire\AuthService\Client\Response\JWT\GetPublicKeyResponse;
use Kabiroman\Octawire\AuthService\Client\Response\JWT\ValidateTokenResponse;
use PHPUnit\Framework\TestCase;

class LocalTokenValidatorTest extends TestCase
{
    private AuthClientFactory $clientFactory;
    private LocalTokenValidator $validator;

    protected function setUp(): void
    {
        $this->clientFactory = $this->createMock(AuthClientFactory::class);
        $this->validator = new LocalTokenValidator($this->clientFactory);
    }

    public function testValidateTokenReturnsInvalidForMalformedToken(): void
    {
        $result = $this->validator->validateToken('invalid-token');

        $this->assertInstanceOf(ValidateTokenResponse::class, $result);
        $this->assertFalse($result->valid);
        $this->assertEquals('INVALID_FORMAT', $result->errorCode);
    }

    public function testValidateTokenReturnsInvalidForInvalidHeader(): void
    {
        $token = 'invalid.header.signature';
        $result = $this->validator->validateToken($token);

        $this->assertInstanceOf(ValidateTokenResponse::class, $result);
        $this->assertFalse($result->valid);
    }

    public function testValidateTokenReturnsInvalidWhenPublicKeyNotFound(): void
    {
        // Create a valid JWT structure
        $header = base64_encode(json_encode(['alg' => 'RS256', 'kid' => 'test-key']));
        $payload = base64_encode(json_encode(['sub' => 'user-123', 'exp' => time() + 3600]));
        $token = str_replace(['+', '/', '='], ['-', '_', ''], $header) . '.' .
                 str_replace(['+', '/', '='], ['-', '_', ''], $payload) . '.signature';

        $this->clientFactory
            ->expects($this->once())
            ->method('getDefaultProjectId')
            ->willReturn('default-project');

        $client = $this->createMock(AuthClient::class);
        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with('default-project')
            ->willReturn($client);

        $client
            ->expects($this->once())
            ->method('getPublicKey')
            ->with($this->isInstanceOf(GetPublicKeyRequest::class))
            ->willReturn(new GetPublicKeyResponse(
                publicKeyPem: '',
                algorithm: 'RS256',
                keyId: 'test-key',
                projectId: 'default-project',
                cacheUntil: time() + 3600,
                activeKeys: []
            ));

        $result = $this->validator->validateToken($token);

        $this->assertInstanceOf(ValidateTokenResponse::class, $result);
        $this->assertFalse($result->valid);
        $this->assertEquals('KEY_NOT_FOUND', $result->errorCode);
    }

    public function testGetPublicKeyUsesCache(): void
    {
        // This test would require mocking internal cache, which is private
        // For now, we test that getPublicKey is called correctly
        $this->markTestSkipped('Cache testing requires refactoring to make cache testable');
    }

    public function testGetPublicKeyValidatesWhitelist(): void
    {
        $projectId = 'test-project';
        $keyId = 'test-key';

        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with($projectId)
            ->willThrowException(new \InvalidArgumentException('Project not allowed'));

        // Use reflection to test private method
        $reflection = new \ReflectionClass($this->validator);
        $method = $reflection->getMethod('getPublicKey');
        $method->setAccessible(true);

        $result = $method->invoke($this->validator, $projectId, $keyId);

        $this->assertNull($result);
    }

    public function testFindPrimaryKeyReturnsPrimaryKey(): void
    {
        $primaryKey = new PublicKeyInfo(
            keyId: 'primary-key',
            publicKeyPem: 'test-key',
            isPrimary: true,
            expiresAt: time() + 3600
        );

        $secondaryKey = new PublicKeyInfo(
            keyId: 'secondary-key',
            publicKeyPem: 'test-key-2',
            isPrimary: false,
            expiresAt: time() + 3600
        );

        $response = new GetPublicKeyResponse(
            publicKeyPem: 'test-key',
            algorithm: 'RS256',
            keyId: 'primary-key',
            projectId: 'test-project',
            cacheUntil: time() + 3600,
            activeKeys: [
                $primaryKey->toArray(),
                $secondaryKey->toArray(),
            ]
        );

        $reflection = new \ReflectionClass($this->validator);
        $method = $reflection->getMethod('findPrimaryKey');
        $method->setAccessible(true);

        $result = $method->invoke($this->validator, $response);

        $this->assertNotNull($result);
        $this->assertTrue($result->isPrimary);
        $this->assertEquals('primary-key', $result->keyId);
    }
}

