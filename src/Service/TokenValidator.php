<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Service;

use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;
use Kabiroman\Octawire\AuthService\Bundle\Service\LocalTokenValidator;
use Kabiroman\Octawire\AuthService\Bundle\Service\ServiceAuthProvider;
use Kabiroman\Octawire\AuthService\Client\Exception\AuthException;
use Kabiroman\Octawire\AuthService\Client\Exception\InvalidTokenException;
use Kabiroman\Octawire\AuthService\Client\Exception\TokenExpiredException;
use Kabiroman\Octawire\AuthService\Client\Exception\TokenRevokedException;
use Kabiroman\Octawire\AuthService\Client\Request\JWT\IssueServiceTokenRequest;
use Kabiroman\Octawire\AuthService\Client\Request\JWT\ValidateTokenRequest;
use Kabiroman\Octawire\AuthService\Client\Response\JWT\ValidateTokenResponse;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * Service for validating JWT tokens through AuthClient
 */
class TokenValidator
{
    private AuthClientFactory $clientFactory;
    private string $validationMode;
    private bool $checkBlacklist;
    private ?LocalTokenValidator $localValidator;
    private ServiceAuthProvider $serviceAuthProvider;
    /**
     * Per-project cached service tokens: project_id -> ['token' => string, 'expires_at' => int]
     *
     * @var array<string, array{token: string, expires_at: int}>
     */
    private array $cachedServiceTokens = [];

    public function __construct(
        AuthClientFactory $clientFactory,
        string $validationMode = 'remote',
        bool $checkBlacklist = true,
        ?LocalTokenValidator $localValidator = null,
        ?ServiceAuthProvider $serviceAuthProvider = null
    ) {
        $this->clientFactory = $clientFactory;
        $this->validationMode = $validationMode;
        $this->checkBlacklist = $checkBlacklist;
        $this->localValidator = $localValidator;
        $this->serviceAuthProvider = $serviceAuthProvider ?? new ServiceAuthProvider();
    }

    /**
     * Validate a JWT token
     *
     * @param string $token JWT token to validate
     * @param string|null $projectId Project ID (optional, will use default if not provided)
     * @return ValidateTokenResponse Validation response with claims
     * @throws AuthenticationException If token is invalid
     */
    public function validateToken(string $token, ?string $projectId = null): ValidateTokenResponse
    {
        if ($this->validationMode === 'remote') {
            return $this->validateRemote($token, $projectId);
        }

        if ($this->validationMode === 'local') {
            if ($this->localValidator === null) {
                throw new \RuntimeException('LocalTokenValidator is required for local validation mode.');
            }
            return $this->localValidator->validateToken($token, $projectId);
        }

        // hybrid mode
        if ($this->localValidator === null) {
            throw new \RuntimeException('LocalTokenValidator is required for hybrid validation mode.');
        }

        $localResult = $this->localValidator->validateToken($token, $projectId);
        if (!$localResult->valid) {
            return $localResult;
        }

        if ($this->checkBlacklist) {
            return $this->checkBlacklistRemote($token, $projectId, $localResult);
        }

        return $localResult;
    }

    /**
     * Validate token remotely (full validation via Auth Service)
     *
     * @param string $token JWT token to validate
     * @param string|null $projectId Project ID
     * @return ValidateTokenResponse Validation response
     * @throws AuthenticationException If token is invalid
     */
    private function validateRemote(string $token, ?string $projectId = null): ValidateTokenResponse
    {
        try {
            $client = $this->clientFactory->getClient($projectId);

            // Create ValidateTokenRequest DTO
            $request = new ValidateTokenRequest(
                token: $token,
                checkBlacklist: $this->checkBlacklist
            );

            // Get service token for authentication (if service auth is configured)
            $serviceToken = $this->getServiceToken($client, $projectId);

            // Validate token using service token for authentication
            $response = $client->validateToken($request, $serviceToken);

            if (!$response->valid) {
                throw new BadCredentialsException($response->error ?? 'Token is invalid.');
            }

            return $response;
        } catch (BadCredentialsException $e) {
            // Re-throw BadCredentialsException as-is
            throw $e;
        } catch (TokenExpiredException $e) {
            throw new BadCredentialsException('Token has expired.', 0, $e);
        } catch (TokenRevokedException $e) {
            throw new BadCredentialsException('Token has been revoked.', 0, $e);
        } catch (InvalidTokenException $e) {
            throw new BadCredentialsException('Token is invalid.', 0, $e);
        } catch (\Exception $e) {
            // Log the actual error for debugging
            error_log('TokenValidator::validateRemote error: ' . $e->getMessage() . ' | Trace: ' . $e->getTraceAsString());
            throw new AuthenticationException('Token validation failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Check token blacklist remotely (for hybrid mode)
     *
     * @param string $token JWT token
     * @param string|null $projectId Project ID
     * @param ValidateTokenResponse $localResult Local validation result
     * @return ValidateTokenResponse Validation response
     */
    private function checkBlacklistRemote(string $token, ?string $projectId, ValidateTokenResponse $localResult): ValidateTokenResponse
    {
        try {
            $client = $this->clientFactory->getClient($projectId);

            // Create ValidateTokenRequest DTO with check_blacklist only
            $request = new ValidateTokenRequest(
                token: $token,
                checkBlacklist: true
            );

            // Get service token for authentication
            $serviceToken = $this->getServiceToken($client, $projectId);

            // Validate token (blacklist check only)
            $response = $client->validateToken($request, $serviceToken);

            // If blacklist check fails, return error
            if (!$response->valid) {
                return $response;
            }

            // Return local result (signature already verified)
            return $localResult;
        } catch (\Exception $e) {
            // If blacklist check fails, return error
            return new ValidateTokenResponse(
                valid: false,
                error: 'Blacklist check failed: ' . $e->getMessage(),
                errorCode: 'BLACKLIST_CHECK_FAILED'
            );
        }
    }

    /**
     * Extract project ID from token claims (if available)
     *
     * @param string $token JWT token
     * @return string|null Project ID from token, or null if not found
     */
    public function extractProjectIdFromToken(string $token): ?string
    {
        try {
            // Try to parse token without validation to extract project_id from claims
            // This is a fallback - the token should contain project_id in its claims
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                return null;
            }

            $decoded = base64_decode(strtr($parts[1], '-_', '+/'), true);
            if ($decoded === false) {
                return null;
            }

            $payload = json_decode($decoded, true);
            if (!is_array($payload)) {
                return null;
            }

            return $payload['project_id'] ?? $payload['aud'] ?? null;
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Get service token for authentication (with caching)
     *
     * @param \Kabiroman\Octawire\AuthService\Client\AuthClient $client AuthClient instance
     * @param string|null $projectId Project ID
     * @return string|null Service token, or null if service auth is not configured
     */
    private function getServiceToken($client, ?string $projectId): ?string
    {
        // If project_id is not provided, cannot get service auth
        if ($projectId === null) {
            return null;
        }

        // Get service auth for this project
        $serviceAuth = $this->serviceAuthProvider->getServiceAuth($projectId);
        if ($serviceAuth === null) {
            // Service auth is not configured for this project, return null (will use apiKey from config)
            return null;
        }

        $serviceName = $serviceAuth['service_name'];
        $serviceSecret = $serviceAuth['service_secret'];

        // Check if cached token is still valid (with 60 seconds buffer)
        if (isset($this->cachedServiceTokens[$projectId])) {
            $cached = $this->cachedServiceTokens[$projectId];
            if (time() < ($cached['expires_at'] - 60)) {
                return $cached['token'];
            }
        }

        // Issue new service token
        try {
            $request = new IssueServiceTokenRequest(
                sourceService: $serviceName,
                projectId: $projectId
            );

            $response = $client->issueServiceToken($request, $serviceSecret);

            // Parse token to get expiration (with fallback to 1 hour)
            $expiresAt = time() + 3600;
            try {
                $parts = explode('.', $response->accessToken);
                if (count($parts) === 3) {
                    $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
                    $expiresAt = $payload['exp'] ?? (time() + 3600);
                }
            } catch (\Exception $e) {
                // Use default expiration
            }

            // Cache the token per project
            $this->cachedServiceTokens[$projectId] = [
                'token' => $response->accessToken,
                'expires_at' => $expiresAt,
            ];

            return $response->accessToken;
        } catch (AuthException $e) {
            // Special handling for AUTH_FAILED error code
            if ($e->getErrorCode() === 'AUTH_FAILED') {
                error_log('Service authentication failed: Invalid service credentials (service_name: ' . $serviceName . ', project_id: ' . $projectId . ')');
                throw new AuthenticationException(
                    'Service authentication failed: Invalid service credentials. Check service_name and service_secret configuration for project ' . $projectId . '.',
                    0,
                    $e
                );
            }
            error_log('Failed to issue service token: ' . $e->getMessage());
            throw new AuthenticationException('Service authentication failed: ' . $e->getMessage(), 0, $e);
        } catch (\Exception $e) {
            // If service token issuance fails, surface the error
            error_log('Failed to issue service token: ' . $e->getMessage());
            throw new AuthenticationException('Service authentication failed: ' . $e->getMessage(), 0, $e);
        }
    }
}

