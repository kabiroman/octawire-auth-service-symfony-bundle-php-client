<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Unit\Service;

use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;
use Kabiroman\Octawire\AuthService\Bundle\Service\Cache\KeyCacheInterface;
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
        $projectId = 'project-1';
        $keyId = 'key-1';
        $cache = new TestKeyCache();
        $validator = new LocalTokenValidator($this->clientFactory, $cache);

        $client = $this->createMock(AuthClient::class);
        $this->clientFactory
            ->expects($this->once())
            ->method('getClient')
            ->with($projectId)
            ->willReturn($client);

        $response = $this->createGetPublicKeyResponse('PUBLIC_KEY', time() + 300);
        $client
            ->expects($this->once())
            ->method('getPublicKey')
            ->with($this->isInstanceOf(GetPublicKeyRequest::class))
            ->willReturn($response);

        $result1 = $this->invokeGetPublicKey($validator, $projectId, $keyId);
        $result2 = $this->invokeGetPublicKey($validator, $projectId, $keyId);

        $this->assertEquals('PUBLIC_KEY', $result1);
        $this->assertEquals('PUBLIC_KEY', $result2);
        $this->assertSame(1, $cache->getHits);
    }

    public function testGetPublicKeyRefreshesCacheWhenExpired(): void
    {
        $projectId = 'project-1';
        $keyId = 'key-1';
        $cache = new TestKeyCache();
        $validator = new LocalTokenValidator($this->clientFactory, $cache);

        $client = $this->createMock(AuthClient::class);
        $this->clientFactory
            ->expects($this->exactly(2))
            ->method('getClient')
            ->with($projectId)
            ->willReturn($client);

        $responseExpired = $this->createGetPublicKeyResponse('EXPIRED_KEY', time() - 10);
        $responseFresh = $this->createGetPublicKeyResponse('FRESH_KEY', time() + 300);

        $client
            ->expects($this->exactly(2))
            ->method('getPublicKey')
            ->willReturnOnConsecutiveCalls($responseExpired, $responseFresh);

        $result1 = $this->invokeGetPublicKey($validator, $projectId, $keyId);
        $result2 = $this->invokeGetPublicKey($validator, $projectId, $keyId);

        $this->assertEquals('FRESH_KEY', $result2);
        $this->assertSame(1, $cache->deleteCount);
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

    private function invokeGetPublicKey(LocalTokenValidator $validator, ?string $projectId, ?string $keyId): ?string
    {
        $method = new \ReflectionMethod(LocalTokenValidator::class, 'getPublicKey');
        $method->setAccessible(true);

        return $method->invoke($validator, $projectId, $keyId);
    }

    private function createGetPublicKeyResponse(string $publicKey, int $cacheUntil): GetPublicKeyResponse
    {
        $primaryKey = [
            'key_id' => 'key-1',
            'public_key_pem' => $publicKey,
            'is_primary' => true,
            'expires_at' => time() + 600,
        ];

        return new GetPublicKeyResponse(
            publicKeyPem: $publicKey,
            algorithm: 'RS256',
            keyId: 'key-1',
            projectId: 'project-1',
            cacheUntil: $cacheUntil,
            activeKeys: [$primaryKey]
        );
    }
}

class TestKeyCache implements KeyCacheInterface
{
    /**
     * @var array<string, array{key: string, expires: int}>
     */
    private array $storage = [];

    public int $getHits = 0;
    public int $deleteCount = 0;

    public function get(string $key): ?array
    {
        $this->getHits += isset($this->storage[$key]) ? 1 : 0;
        return $this->storage[$key] ?? null;
    }

    public function set(string $key, string $publicKey, int $expiresAt): void
    {
        $this->storage[$key] = [
            'key' => $publicKey,
            'expires' => $expiresAt,
        ];
    }

    public function delete(string $key): void
    {
        $this->deleteCount++;
        unset($this->storage[$key]);
    }
}

