<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\DependencyInjection;

use Kabiroman\Octawire\AuthService\Client\AuthClient;
use Kabiroman\Octawire\AuthService\Client\Config;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\DependencyInjection\Reference;

/**
 * DependencyInjection Extension for Octawire Auth Bundle
 */
class OctawireAuthExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../../config'));
        $loader->load('services.yaml');

        // Register default project
        $defaultProject = $config['default_project'] ?? null;
        $container->setParameter('octawire_auth.default_project', $defaultProject);

        // Register AuthClient for each project
        $projects = $config['projects'] ?? [];
        $projectIds = [];

        foreach ($projects as $projectName => $projectConfig) {
            $projectId = $projectConfig['project_id'];
            $projectIds[] = $projectId;

            // Create Config instance
            $configServiceId = sprintf('octawire_auth.config.%s', $projectId);
            $configDefinition = new Definition(Config::class);
            $configDefinition->setArguments([$this->buildConfigArray($projectConfig)]);
            $configDefinition->setPublic(true);
            $container->setDefinition($configServiceId, $configDefinition);

            // Create AuthClient instance
            $clientId = sprintf('octawire_auth.client.%s', $projectId);
            $clientDefinition = new Definition(AuthClient::class);
            $clientDefinition->setArguments([new Reference($configServiceId)]);
            $clientDefinition->setPublic(true);
            $container->setDefinition($clientId, $clientDefinition);
        }

        // Register project IDs parameter
        $container->setParameter('octawire_auth.projects', $projectIds);

        // Register factory service with proper arguments
        $factoryDefinition = $container->getDefinition('octawire_auth.client_factory');
        $factoryDefinition->setArguments([
            new Reference('service_container'),
            $projectIds,
            $config['default_project'] ?? null,
        ]);

        // Get validation mode and check_blacklist from config
        $validationMode = $config['validation_mode'] ?? 'remote';
        $checkBlacklist = $config['check_blacklist'] ?? true;

        // Extract service auth from first project config (service auth is per-project)
        $serviceName = null;
        $serviceSecret = null;
        if (!empty($projects)) {
            $firstProjectConfig = reset($projects);
            if (isset($firstProjectConfig['service_auth'])) {
                $serviceName = $firstProjectConfig['service_auth']['service_name'] ?? null;
                $serviceSecret = $firstProjectConfig['service_auth']['service_secret'] ?? null;
            }
        }

        // Register LocalTokenValidator if needed (local or hybrid mode)
        if (in_array($validationMode, ['local', 'hybrid'], true)) {
            $localValidatorDefinition = new Definition(\Kabiroman\Octawire\AuthService\Bundle\Service\LocalTokenValidator::class);
            $localValidatorDefinition->setArguments([
                new Reference('octawire_auth.client_factory'),
            ]);
            $localValidatorDefinition->setPublic(false);
            $container->setDefinition('octawire_auth.local_token_validator', $localValidatorDefinition);
        }

        // Update TokenValidator with validation mode, check_blacklist, and service auth
        $tokenValidatorDefinition = $container->getDefinition('octawire_auth.token_validator');
        $tokenValidatorDefinition->setArguments([
            new Reference('octawire_auth.client_factory'),
            $validationMode,
            $checkBlacklist,
            in_array($validationMode, ['local', 'hybrid'], true) ? new Reference('octawire_auth.local_token_validator') : null,
            $serviceName,
            $serviceSecret,
        ]);
    }

    /**
     * Build config array from project configuration
     */
    private function buildConfigArray(array $projectConfig): array
    {
        $config = [
            'transport' => $projectConfig['transport'] ?? 'tcp',
            'project_id' => $projectConfig['project_id'],
        ];

        // TCP configuration (required for TCP transport)
        if (isset($projectConfig['tcp'])) {
            $config['tcp'] = $projectConfig['tcp'];
        } elseif (isset($projectConfig['address'])) {
            // Legacy support: convert address to TCP config
            [$host, $port] = explode(':', $projectConfig['address'], 2) + ['localhost', '50052'];
            $config['tcp'] = [
                'host' => $host,
                'port' => (int)$port,
            ];
            
            // If TLS was configured at root level, move it to tcp.tls
            if (isset($projectConfig['tls'])) {
                $config['tcp']['tls'] = $projectConfig['tls'];
            }
        }

        if (isset($projectConfig['api_key'])) {
            $config['api_key'] = $projectConfig['api_key'];
        }

        if (isset($projectConfig['retry'])) {
            $config['retry'] = $projectConfig['retry'];
        }

        if (isset($projectConfig['key_cache'])) {
            $config['key_cache'] = $projectConfig['key_cache'];
        }

        if (isset($projectConfig['redis'])) {
            $config['redis'] = $projectConfig['redis'];
        }

        if (isset($projectConfig['timeout'])) {
            $config['timeout'] = $projectConfig['timeout'];
        }

        return $config;
    }

    public function getAlias(): string
    {
        return 'octawire_auth';
    }
}

