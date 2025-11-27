<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Unit\Service;

use Kabiroman\Octawire\AuthService\Bundle\Service\ServiceAuthProvider;
use PHPUnit\Framework\TestCase;

class ServiceAuthProviderTest extends TestCase
{
    public function testGetServiceNameReturnsNullWhenNotConfigured(): void
    {
        $provider = new ServiceAuthProvider();
        
        $this->assertNull($provider->getServiceName('non-existent-project'));
    }

    public function testGetServiceSecretReturnsNullWhenNotConfigured(): void
    {
        $provider = new ServiceAuthProvider();
        
        $this->assertNull($provider->getServiceSecret('non-existent-project'));
    }

    public function testHasServiceAuthReturnsFalseWhenNotConfigured(): void
    {
        $provider = new ServiceAuthProvider();
        
        $this->assertFalse($provider->hasServiceAuth('non-existent-project'));
    }

    public function testGetServiceAuthReturnsNullWhenNotConfigured(): void
    {
        $provider = new ServiceAuthProvider();
        
        $this->assertNull($provider->getServiceAuth('non-existent-project'));
    }

    public function testGetServiceNameReturnsConfiguredValue(): void
    {
        $serviceAuthMap = [
            'project-1' => [
                'service_name' => 'api-gateway',
                'service_secret' => 'secret-123',
            ],
        ];
        
        $provider = new ServiceAuthProvider($serviceAuthMap);
        
        $this->assertEquals('api-gateway', $provider->getServiceName('project-1'));
    }

    public function testGetServiceSecretReturnsConfiguredValue(): void
    {
        $serviceAuthMap = [
            'project-1' => [
                'service_name' => 'api-gateway',
                'service_secret' => 'secret-123',
            ],
        ];
        
        $provider = new ServiceAuthProvider($serviceAuthMap);
        
        $this->assertEquals('secret-123', $provider->getServiceSecret('project-1'));
    }

    public function testHasServiceAuthReturnsTrueWhenConfigured(): void
    {
        $serviceAuthMap = [
            'project-1' => [
                'service_name' => 'api-gateway',
                'service_secret' => 'secret-123',
            ],
        ];
        
        $provider = new ServiceAuthProvider($serviceAuthMap);
        
        $this->assertTrue($provider->hasServiceAuth('project-1'));
    }

    public function testGetServiceAuthReturnsConfiguredValue(): void
    {
        $serviceAuthMap = [
            'project-1' => [
                'service_name' => 'api-gateway',
                'service_secret' => 'secret-123',
            ],
        ];
        
        $provider = new ServiceAuthProvider($serviceAuthMap);
        
        $auth = $provider->getServiceAuth('project-1');
        
        $this->assertNotNull($auth);
        $this->assertEquals('api-gateway', $auth['service_name']);
        $this->assertEquals('secret-123', $auth['service_secret']);
    }

    public function testSupportsMultipleProjects(): void
    {
        $serviceAuthMap = [
            'project-1' => [
                'service_name' => 'api-gateway',
                'service_secret' => 'secret-123',
            ],
            'project-2' => [
                'service_name' => 'internal-api',
                'service_secret' => 'secret-456',
            ],
        ];
        
        $provider = new ServiceAuthProvider($serviceAuthMap);
        
        $this->assertEquals('api-gateway', $provider->getServiceName('project-1'));
        $this->assertEquals('secret-123', $provider->getServiceSecret('project-1'));
        
        $this->assertEquals('internal-api', $provider->getServiceName('project-2'));
        $this->assertEquals('secret-456', $provider->getServiceSecret('project-2'));
    }

    public function testIgnoresIncompleteServiceAuth(): void
    {
        $serviceAuthMap = [
            'project-1' => [
                'service_name' => 'api-gateway',
                // service_secret missing
            ],
            'project-2' => [
                // service_name missing
                'service_secret' => 'secret-456',
            ],
            'project-3' => [
                'service_name' => 'complete-service',
                'service_secret' => 'secret-789',
            ],
        ];
        
        $provider = new ServiceAuthProvider($serviceAuthMap);
        
        // Incomplete entries should be ignored
        $this->assertFalse($provider->hasServiceAuth('project-1'));
        $this->assertFalse($provider->hasServiceAuth('project-2'));
        
        // Only complete entry should be available
        $this->assertTrue($provider->hasServiceAuth('project-3'));
        $this->assertEquals('complete-service', $provider->getServiceName('project-3'));
        $this->assertEquals('secret-789', $provider->getServiceSecret('project-3'));
    }

    public function testIgnoresEmptyServiceAuthMap(): void
    {
        $serviceAuthMap = [
            'project-1' => [],
        ];
        
        $provider = new ServiceAuthProvider($serviceAuthMap);
        
        $this->assertFalse($provider->hasServiceAuth('project-1'));
    }
}

