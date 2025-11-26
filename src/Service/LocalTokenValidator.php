<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Service;

use Firebase\JWT\ExpiredException as JWTExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException as JWTSignatureInvalidException;
use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;
use Kabiroman\Octawire\AuthService\Client\Model\TokenClaims;
use Kabiroman\Octawire\AuthService\Client\Request\JWT\GetPublicKeyRequest;
use Kabiroman\Octawire\AuthService\Client\Response\JWT\GetPublicKeyResponse;
use Kabiroman\Octawire\AuthService\Client\Response\JWT\ValidateTokenResponse;

/**
 * Local token validator for JWT signature verification
 */
class LocalTokenValidator
{
    private AuthClientFactory $clientFactory;
    
    /**
     * Cache for public keys: projectId_keyId => ['key' => string, 'expires' => int]
     * @var array<string, array{key: string, expires: int}>
     */
    private array $keyCache = [];

    public function __construct(AuthClientFactory $clientFactory)
    {
        $this->clientFactory = $clientFactory;
    }

    /**
     * Validate JWT token locally (signature and expiration only)
     *
     * @param string $token JWT token to validate
     * @param string|null $projectId Project ID (optional, will use default if not provided)
     * @return ValidateTokenResponse Validation response
     */
    public function validateToken(string $token, ?string $projectId = null): ValidateTokenResponse
    {
        try {
            // 1. Parse JWT token (header.payload.signature)
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                return new ValidateTokenResponse(
                    valid: false,
                    error: 'Invalid token format',
                    errorCode: 'INVALID_FORMAT'
                );
            }

            // 2. Decode header to get key_id and algorithm
            $header = $this->decodeBase64Url($parts[0]);
            if ($header === null) {
                return new ValidateTokenResponse(
                    valid: false,
                    error: 'Invalid token header',
                    errorCode: 'INVALID_HEADER'
                );
            }

            $headerData = json_decode($header, true);
            if (!is_array($headerData)) {
                return new ValidateTokenResponse(
                    valid: false,
                    error: 'Invalid token header format',
                    errorCode: 'INVALID_HEADER'
                );
            }

            $keyId = $headerData['kid'] ?? null;
            $algorithm = $headerData['alg'] ?? 'RS256';

            // 3. Get public key
            $publicKey = $this->getPublicKey($projectId, $keyId);
            if ($publicKey === null) {
                return new ValidateTokenResponse(
                    valid: false,
                    error: 'Public key not found',
                    errorCode: 'KEY_NOT_FOUND'
                );
            }

            // 4. Verify signature using JWT library
            try {
                // JWT::decode automatically checks exp, so we don't need to check it manually
                $decoded = JWT::decode($token, new Key($publicKey, $algorithm));
            } catch (JWTExpiredException $e) {
                return new ValidateTokenResponse(
                    valid: false,
                    error: 'Token has expired',
                    errorCode: 'TOKEN_EXPIRED'
                );
            } catch (JWTSignatureInvalidException $e) {
                return new ValidateTokenResponse(
                    valid: false,
                    error: 'Invalid token signature: ' . $e->getMessage(),
                    errorCode: 'INVALID_SIGNATURE'
                );
            } catch (\Exception $e) {
                return new ValidateTokenResponse(
                    valid: false,
                    error: 'Token validation failed: ' . $e->getMessage(),
                    errorCode: 'VALIDATION_ERROR'
                );
            }

            // 6. Extract claims
            $claims = $this->extractClaimsFromDecoded($decoded);

            // 7. Return ValidateTokenResponse
            return new ValidateTokenResponse(
                valid: true,
                claims: $claims
            );
        } catch (\Exception $e) {
            return new ValidateTokenResponse(
                valid: false,
                error: 'Token validation failed: ' . $e->getMessage(),
                errorCode: 'VALIDATION_ERROR'
            );
        }
    }

    /**
     * Get public key for project (with caching)
     *
     * @param string|null $projectId Project ID
     * @param string|null $keyId Key ID from token header
     * @return string|null Public key PEM or null if not found
     */
    private function getPublicKey(?string $projectId, ?string $keyId): ?string
    {
        // Create cache key
        $cacheKey = ($projectId ?? 'default') . '_' . ($keyId ?? 'default');

        // Check cache
        if (isset($this->keyCache[$cacheKey])) {
            $cached = $this->keyCache[$cacheKey];
            if ($cached['expires'] > time()) {
                return $cached['key'];
            }
            // Cache expired, remove it
            unset($this->keyCache[$cacheKey]);
        }

        try {
            // Determine project_id for request
            $requestProjectId = $projectId;
            if ($requestProjectId === null) {
                // Need project_id for GetPublicKey request
                // Try to get default project
                $defaultProjectId = $this->clientFactory->getDefaultProjectId();
                if ($defaultProjectId === null) {
                    return null;
                }
                $requestProjectId = $defaultProjectId;
            }

            // Get client for project (this validates whitelist via AuthClientFactory)
            $client = $this->clientFactory->getClient($requestProjectId);

            $request = new GetPublicKeyRequest(
                projectId: $requestProjectId,
                keyId: $keyId
            );

            // Get public key from Auth Service
            $response = $client->getPublicKey($request);

            // Cache the primary key
            $primaryKey = $this->findPrimaryKey($response);
            if ($primaryKey !== null) {
                $this->keyCache[$cacheKey] = [
                    'key' => $primaryKey->publicKeyPem,
                    'expires' => $response->cacheUntil
                ];
                return $primaryKey->publicKeyPem;
            }

            // Fallback to publicKeyPem if no primary key found
            if (!empty($response->publicKeyPem)) {
                $this->keyCache[$cacheKey] = [
                    'key' => $response->publicKeyPem,
                    'expires' => $response->cacheUntil
                ];
                return $response->publicKeyPem;
            }

            return null;
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Find primary key from active keys
     *
     * @param GetPublicKeyResponse $response Response with active keys
     * @return \Kabiroman\Octawire\AuthService\Client\Model\PublicKeyInfo|null Primary key or null
     */
    private function findPrimaryKey(GetPublicKeyResponse $response): ?\Kabiroman\Octawire\AuthService\Client\Model\PublicKeyInfo
    {
        foreach ($response->activeKeys as $keyInfo) {
            if ($keyInfo->isPrimary && !$keyInfo->isExpired()) {
                return $keyInfo;
            }
        }
        return null;
    }

    /**
     * Extract claims from decoded JWT
     *
     * @param object $decoded Decoded JWT object
     * @return TokenClaims Token claims
     */
    private function extractClaimsFromDecoded(object $decoded): TokenClaims
    {
        // Convert decoded object to array
        $decodedArray = json_decode(json_encode($decoded), true);
        if (!is_array($decodedArray)) {
            $decodedArray = [];
        }

        return TokenClaims::fromArray($decodedArray);
    }

    /**
     * Decode base64url string
     *
     * @param string $data Base64url encoded string
     * @return string|null Decoded string or null on failure
     */
    private function decodeBase64Url(string $data): ?string
    {
        // Add padding if needed
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $data .= str_repeat('=', $padlen);
        }

        // Replace URL-safe characters
        $data = strtr($data, '-_', '+/');

        $decoded = base64_decode($data, true);
        if ($decoded === false) {
            return null;
        }

        return $decoded;
    }
}

