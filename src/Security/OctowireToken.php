<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Security;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

/**
 * Token for Octawire authentication
 */
class OctowireToken extends AbstractToken
{
    private string $jwtToken;
    private ?string $projectId;
    private array $claims;

    /**
     * @param string $jwtToken Original JWT token
     * @param string|null $projectId Project ID
     * @param array $claims Token claims
     * @param array<string> $roles User roles
     */
    public function __construct(
        string $jwtToken,
        ?string $projectId,
        array $claims = [],
        array $roles = []
    ) {
        parent::__construct($roles);

        $this->jwtToken = $jwtToken;
        $this->projectId = $projectId;
        $this->claims = $claims;

        $this->setAuthenticated(count($roles) > 0);
    }

    /**
     * Get the original JWT token
     */
    public function getJwtToken(): string
    {
        return $this->jwtToken;
    }

    /**
     * Get project ID
     */
    public function getProjectId(): ?string
    {
        return $this->projectId;
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
     * Get user ID from claims
     */
    public function getUserId(): ?string
    {
        return $this->claims['user_id'] ?? $this->claims['sub'] ?? null;
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials(): string
    {
        return $this->jwtToken;
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials(): void
    {
        parent::eraseCredentials();
        // JWT token is kept for potential use in request handling
    }
}




