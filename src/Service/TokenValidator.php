<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Service;

use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;
use Kabiroman\Octawire\AuthService\Bundle\Service\LocalTokenValidator;
use Kabiroman\Octawire\AuthService\Client\Exception\InvalidTokenException;
use Kabiroman\Octawire\AuthService\Client\Exception\TokenExpiredException;
use Kabiroman\Octawire\AuthService\Client\Exception\TokenRevokedException;
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

    public function __construct(
        AuthClientFactory $clientFactory,
        string $validationMode = 'remote',
        bool $checkBlacklist = true,
        ?LocalTokenValidator $localValidator = null
    ) {
        $this->clientFactory = $clientFactory;
        $this->validationMode = $validationMode;
        $this->checkBlacklist = $checkBlacklist;
        $this->localValidator = $localValidator;
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

            // ValidateToken requires JWT token for authentication (second parameter)
            $response = $client->validateToken($request, $token);

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
            throw new AuthenticationException('Token validation failed.', 0, $e);
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

            // ValidateToken requires JWT token for authentication (second parameter)
            $response = $client->validateToken($request, $token);

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
}

