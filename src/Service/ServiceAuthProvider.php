<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Service;

/**
 * Service for providing service authentication credentials per project
 */
class ServiceAuthProvider
{
    /**
     * Mapping: project_id -> ['service_name' => string, 'service_secret' => string]
     *
     * @var array<string, array{service_name: string, service_secret: string}>
     */
    private array $serviceAuthMap = [];

    /**
     * @param array<string, array{service_name?: string, service_secret?: string}> $serviceAuthMap
     */
    public function __construct(array $serviceAuthMap = [])
    {
        foreach ($serviceAuthMap as $projectId => $auth) {
            if (isset($auth['service_name']) && isset($auth['service_secret'])) {
                $this->serviceAuthMap[$projectId] = [
                    'service_name' => $auth['service_name'],
                    'service_secret' => $auth['service_secret'],
                ];
            }
        }
    }

    /**
     * Get service name for a project
     *
     * @param string $projectId Project ID
     * @return string|null Service name, or null if not configured
     */
    public function getServiceName(string $projectId): ?string
    {
        return $this->serviceAuthMap[$projectId]['service_name'] ?? null;
    }

    /**
     * Get service secret for a project
     *
     * @param string $projectId Project ID
     * @return string|null Service secret, or null if not configured
     */
    public function getServiceSecret(string $projectId): ?string
    {
        return $this->serviceAuthMap[$projectId]['service_secret'] ?? null;
    }

    /**
     * Check if service auth is configured for a project
     *
     * @param string $projectId Project ID
     * @return bool True if service auth is configured
     */
    public function hasServiceAuth(string $projectId): bool
    {
        return isset($this->serviceAuthMap[$projectId]);
    }

    /**
     * Get service auth for a project
     *
     * @param string $projectId Project ID
     * @return array{service_name: string, service_secret: string}|null Service auth, or null if not configured
     */
    public function getServiceAuth(string $projectId): ?array
    {
        return $this->serviceAuthMap[$projectId] ?? null;
    }
}

