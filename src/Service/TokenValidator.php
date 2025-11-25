<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Service;

use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;
use Kabiroman\Octawire\AuthService\Client\Exception\InvalidTokenException;
use Kabiroman\Octawire\AuthService\Client\Exception\TokenExpiredException;
use Kabiroman\Octawire\AuthService\Client\Exception\TokenRevokedException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * Service for validating JWT tokens through AuthClient
 */
class TokenValidator
{
    private AuthClientFactory $clientFactory;

    public function __construct(AuthClientFactory $clientFactory)
    {
        $this->clientFactory = $clientFactory;
    }

    /**
     * Validate a JWT token
     *
     * @param string $token JWT token to validate
     * @param string|null $projectId Project ID (optional, will use default if not provided)
     * @return array Validation response with claims
     * @throws AuthenticationException If token is invalid
     */
    public function validateToken(string $token, ?string $projectId = null): array
    {
        try {
            $client = $this->clientFactory->getClient($projectId);

            // ValidateToken requires JWT token for authentication
            $response = $client->validateToken([
                'token' => $token,
                'check_blacklist' => true,
                'jwt_token' => $token, // Use the token itself for auth
            ]);

            if (!$response['valid'] ?? false) {
                throw new BadCredentialsException('Token is invalid.');
            }

            return $response;
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

