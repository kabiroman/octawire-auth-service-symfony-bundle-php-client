<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Unit\Factory;

use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;
use Kabiroman\Octawire\AuthService\Client\AuthClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

class AuthClientFactoryTest extends TestCase
{
    private ContainerInterface $container;
    private AuthClientFactory $factory;

    protected function setUp(): void
    {
        $this->container = $this->createMock(ContainerInterface::class);
        $this->factory = new AuthClientFactory(
            $this->container,
            ['project-1', 'project-2'],
            'project-1'
        );
    }

    public function testGetClientWithDefaultProject(): void
    {
        $client = $this->createMock(AuthClient::class);

        $this->container
            ->expects($this->once())
            ->method('has')
            ->with('octawire_auth.client.project-1')
            ->willReturn(true);

        $this->container
            ->expects($this->once())
            ->method('get')
            ->with('octawire_auth.client.project-1')
            ->willReturn($client);

        $result = $this->factory->getClient();

        $this->assertEquals($client, $result);
    }

    public function testGetClientWithSpecificProject(): void
    {
        $client = $this->createMock(AuthClient::class);

        $this->container
            ->expects($this->once())
            ->method('has')
            ->with('octawire_auth.client.project-2')
            ->willReturn(true);

        $this->container
            ->expects($this->once())
            ->method('get')
            ->with('octawire_auth.client.project-2')
            ->willReturn($client);

        $result = $this->factory->getClient('project-2');

        $this->assertEquals($client, $result);
    }

    public function testGetClientThrowsExceptionWhenProjectNotConfigured(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Project ID "project-3" is not allowed on this service');

        $this->factory->getClient('project-3');
    }

    public function testGetClientThrowsExceptionWhenNoDefaultProject(): void
    {
        $factory = new AuthClientFactory(
            $this->container,
            ['project-1'],
            null
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Project ID is required');

        $factory->getClient();
    }

    public function testGetClientThrowsExceptionWhenServiceNotFound(): void
    {
        $this->container
            ->expects($this->once())
            ->method('has')
            ->with('octawire_auth.client.project-2')
            ->willReturn(false);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('AuthClient service "octawire_auth.client.project-2" not found');

        $this->factory->getClient('project-2');
    }

    public function testGetDefaultProjectId(): void
    {
        $this->assertEquals('project-1', $this->factory->getDefaultProjectId());
    }

    public function testGetDefaultProjectIdReturnsNull(): void
    {
        $factory = new AuthClientFactory($this->container, [], null);

        $this->assertNull($factory->getDefaultProjectId());
    }

    public function testGetProjectIds(): void
    {
        $projectIds = $this->factory->getProjectIds();

        $this->assertEquals(['project-1', 'project-2'], $projectIds);
    }

    public function testHasProject(): void
    {
        $this->assertTrue($this->factory->hasProject('project-1'));
        $this->assertTrue($this->factory->hasProject('project-2'));
        $this->assertFalse($this->factory->hasProject('project-3'));
    }
}

