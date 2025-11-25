<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Fixtures;

use Kabiroman\Octawire\AuthService\Bundle\OctawireAuthBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;

class TestKernel extends Kernel
{
    private ?string $testCase = null;

    public function __construct(string $environment = 'test', bool $debug = true, ?string $testCase = null)
    {
        parent::__construct($environment, $debug);
        $this->testCase = $testCase;
    }

    public function registerBundles(): iterable
    {
        return [
            new FrameworkBundle(),
            new SecurityBundle(),
            new OctawireAuthBundle(),
        ];
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        // Load base configuration
        $loader->load(__DIR__ . '/config/test_services.yaml');

        // Load test case specific configuration if exists
        if ($this->testCase !== null) {
            $testCaseConfig = __DIR__ . '/config/' . $this->testCase . '.yaml';
            if (file_exists($testCaseConfig)) {
                $loader->load($testCaseConfig);
            }
        }
    }

    public function getProjectDir(): string
    {
        return __DIR__ . '/../..';
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/octawire_bundle_tests/cache/' . $this->environment . ($this->testCase ? '_' . $this->testCase : '');
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/octawire_bundle_tests/logs/' . $this->environment . ($this->testCase ? '_' . $this->testCase : '');
    }

    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->setParameter('kernel.secret', 'test-secret-' . ($this->testCase ?? 'default'));
    }
}

