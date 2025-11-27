<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Functional;

use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;
use Kabiroman\Octawire\AuthService\Bundle\Service\ServiceAuthProvider;
use Kabiroman\Octawire\AuthService\Bundle\Service\TokenValidator;
use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireTokenAuthenticator;
use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireUserProvider;
use Kabiroman\Octawire\AuthService\Client\AuthClient;
use PHPUnit\Framework\TestCase;

class BundleConfigurationTest extends KernelTestCase
{
    public function testBundleRegistersServices(): void
    {
        self::bootKernel();

        $container = self::getContainer();

        $this->assertTrue($container->has('octawire_auth.client_factory'));
        $this->assertTrue($container->has('octawire_auth.token_validator'));
        $this->assertTrue($container->has('octawire_auth.authenticator'));
        $this->assertTrue($container->has('octawire_auth.user_provider'));
        $this->assertTrue($container->has('octawire_auth.service_auth_provider'));
    }

    public function testAuthClientFactoryService(): void
    {
        self::bootKernel();

        $container = self::getContainer();
        $factory = $container->get('octawire_auth.client_factory');

        $this->assertInstanceOf(AuthClientFactory::class, $factory);
        $this->assertEquals('test-project', $factory->getDefaultProjectId());
        $this->assertTrue($factory->hasProject('test-project'));
        $this->assertTrue($factory->hasProject('admin-project'));
    }

    public function testTokenValidatorService(): void
    {
        self::bootKernel();

        $container = self::getContainer();
        $validator = $container->get('octawire_auth.token_validator');

        $this->assertInstanceOf(TokenValidator::class, $validator);
    }

    public function testAuthenticatorService(): void
    {
        self::bootKernel();

        $container = self::getContainer();
        $authenticator = $container->get('octawire_auth.authenticator');

        $this->assertInstanceOf(OctowireTokenAuthenticator::class, $authenticator);
    }

    public function testUserProviderService(): void
    {
        self::bootKernel();

        $container = self::getContainer();
        $userProvider = $container->get('octawire_auth.user_provider');

        $this->assertInstanceOf(OctowireUserProvider::class, $userProvider);
    }

    public function testAuthClientCreatedForProject(): void
    {
        self::bootKernel();

        $container = self::getContainer();
        $factory = $container->get('octawire_auth.client_factory');

        $client = $factory->getClient('test-project');

        $this->assertInstanceOf(AuthClient::class, $client);
    }

    public function testAuthClientCreatedForAdminProject(): void
    {
        self::bootKernel();

        $container = self::getContainer();
        $factory = $container->get('octawire_auth.client_factory');

        $client = $factory->getClient('admin-project');

        $this->assertInstanceOf(AuthClient::class, $client);
    }

    public function testConfigurationLoaded(): void
    {
        self::bootKernel();

        $container = self::getContainer();
        $factory = $container->get('octawire_auth.client_factory');

        $this->assertEqualsCanonicalizing(['test-project', 'admin-project'], $factory->getProjectIds());
        $this->assertEquals('test-project', $factory->getDefaultProjectId());
    }

    public function testServiceAuthProviderService(): void
    {
        self::bootKernel();

        $container = self::getContainer();
        $serviceAuthProvider = $container->get('octawire_auth.service_auth_provider');

        $this->assertInstanceOf(ServiceAuthProvider::class, $serviceAuthProvider);
        
        // Check that service auth is configured for test projects
        $this->assertTrue($serviceAuthProvider->hasServiceAuth('test-project'));
        $this->assertTrue($serviceAuthProvider->hasServiceAuth('admin-project'));
        
        // Check service names
        $this->assertEquals('test-service', $serviceAuthProvider->getServiceName('test-project'));
        $this->assertEquals('internal-api', $serviceAuthProvider->getServiceName('admin-project'));
    }
}

