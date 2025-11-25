<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Factory;

use Kabiroman\Octawire\AuthService\Client\AuthClient;
use Psr\Container\ContainerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface as SymfonyContainerInterface;

/**
 * Factory for creating and managing AuthClient instances
 */
class AuthClientFactory
{
    private SymfonyContainerInterface $container;
    private array $projectIds;
    private ?string $defaultProjectId;

    /**
     * @param SymfonyContainerInterface $container Symfony service container
     * @param array<string> $projectIds List of configured project IDs
     * @param string|null $defaultProjectId Default project ID
     */
    public function __construct(
        SymfonyContainerInterface $container,
        array $projectIds,
        ?string $defaultProjectId = null
    ) {
        $this->container = $container;
        $this->projectIds = $projectIds;
        $this->defaultProjectId = $defaultProjectId;
    }

    /**
     * Get AuthClient for a specific project
     *
     * @param string|null $projectId Project ID, or null to use default
     * @return AuthClient
     * @throws \InvalidArgumentException If project ID is not configured
     */
    public function getClient(?string $projectId = null): AuthClient
    {
        $projectId = $projectId ?? $this->defaultProjectId;

        if ($projectId === null) {
            throw new \InvalidArgumentException(
                'Project ID is required. Either specify it in the request or configure a default project.'
            );
        }

        if (!in_array($projectId, $this->projectIds, true)) {
            throw new \InvalidArgumentException(
                sprintf('Project ID "%s" is not configured. Available projects: %s', $projectId, implode(', ', $this->projectIds))
            );
        }

        $serviceId = sprintf('octawire_auth.client.%s', $projectId);

        if (!$this->container->has($serviceId)) {
            throw new \RuntimeException(sprintf('AuthClient service "%s" not found.', $serviceId));
        }

        return $this->container->get($serviceId);
    }

    /**
     * Get default project ID
     */
    public function getDefaultProjectId(): ?string
    {
        return $this->defaultProjectId;
    }

    /**
     * Get all configured project IDs
     *
     * @return array<string>
     */
    public function getProjectIds(): array
    {
        return $this->projectIds;
    }

    /**
     * Check if a project ID is configured
     */
    public function hasProject(string $projectId): bool
    {
        return in_array($projectId, $this->projectIds, true);
    }
}




