<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * User representation based on JWT token claims
 */
class OctowireUser implements UserInterface
{
    private string $userId;
    private array $claims;
    private array $roles;

    /**
     * @param string $userId User ID
     * @param array<string, mixed> $claims Token claims
     * @param array<string> $roles User roles
     */
    public function __construct(string $userId, array $claims = [], array $roles = [])
    {
        $this->userId = $userId;
        $this->claims = $claims;
        $this->roles = $roles;
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials(): void
    {
        // No credentials to erase for JWT-based authentication
    }

    /**
     * {@inheritdoc}
     */
    public function getUserIdentifier(): string
    {
        return $this->userId;
    }

    /**
     * Get user ID (alias for getUserIdentifier for compatibility)
     */
    public function getUserId(): string
    {
        return $this->userId;
    }

    /**
     * Get all token claims
     *
     * @return array<string, mixed>
     */
    public function getClaims(): array
    {
        return $this->claims;
    }

    /**
     * Get a specific claim
     *
     * @param string $key Claim key
     * @param mixed $default Default value if claim not found
     * @return mixed
     */
    public function getClaim(string $key, mixed $default = null): mixed
    {
        return $this->claims[$key] ?? $default;
    }

    /**
     * Create from token claims
     *
     * @param array<string, mixed> $claims Token claims
     * @param array<string> $roles User roles (extracted from claims if not provided)
     * @return self
     */
    public static function fromClaims(array $claims, array $roles = []): self
    {
        // v0.9.4+ uses camelCase 'userId', with fallback to 'user_id' for compatibility
        $userId = $claims['userId'] ?? $claims['user_id'] ?? $claims['sub'] ?? '';
        $extractedRoles = $roles ?: self::extractRolesFromClaims($claims);

        return new self($userId, $claims, $extractedRoles);
    }

    /**
     * Extract roles from claims
     *
     * @param array<string, mixed> $claims Token claims
     * @return array<string>
     */
    private static function extractRolesFromClaims(array $claims): array
    {
        $roles = [];
        $flattenedClaims = $claims;

        // Merge nested custom claims (snake_case and camelCase) for easier access
        if (isset($claims['custom_claims']) && is_array($claims['custom_claims'])) {
            $flattenedClaims = array_merge($flattenedClaims, $claims['custom_claims']);
        }
        if (isset($claims['customClaims']) && is_array($claims['customClaims'])) {
            $flattenedClaims = array_merge($flattenedClaims, $claims['customClaims']);
        }

        // Check for 'roles' claim
        if (isset($flattenedClaims['roles']) && is_array($flattenedClaims['roles'])) {
            $roles = array_merge($roles, $flattenedClaims['roles']);
        }

        // Check for 'role' claim (single role)
        if (isset($flattenedClaims['role']) && is_string($flattenedClaims['role'])) {
            $roles[] = $flattenedClaims['role'];
        }

        // Add ROLE_USER by default if no roles found
        if (empty($roles)) {
            $roles[] = 'ROLE_USER';
        }

        // Ensure all roles start with ROLE_ prefix
        return array_map(function ($role) {
            if (!str_starts_with($role, 'ROLE_')) {
                return 'ROLE_' . strtoupper($role);
            }
            return strtoupper($role);
        }, array_unique($roles));
    }
}




