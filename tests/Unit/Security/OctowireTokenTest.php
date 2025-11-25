<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Unit\Security;

use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireToken;
use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireUser;
use PHPUnit\Framework\TestCase;

class OctowireTokenTest extends TestCase
{
    public function testTokenCreation(): void
    {
        $jwtToken = 'test.jwt.token';
        $projectId = 'test-project';
        $claims = ['user_id' => 'user-123', 'role' => 'admin'];
        $roles = ['ROLE_USER', 'ROLE_ADMIN'];

        $token = new OctowireToken($jwtToken, $projectId, $claims, $roles);

        $this->assertEquals($jwtToken, $token->getJwtToken());
        $this->assertEquals($projectId, $token->getProjectId());
        $this->assertEquals($claims, $token->getClaims());
        $this->assertEquals($roles, $token->getRoleNames());
        // Token with roles is authenticated - check by presence of roles
        $this->assertNotEmpty($token->getRoleNames());
    }

    public function testTokenWithoutRoles(): void
    {
        $token = new OctowireToken('test.token', 'project-1', [], []);

        // Token without roles - check by empty roles
        $this->assertEmpty($token->getRoleNames());
    }

    public function testGetClaim(): void
    {
        $claims = [
            'user_id' => 'user-123',
            'custom_claim' => 'value',
            'nested' => ['key' => 'value'],
        ];

        $token = new OctowireToken('token', 'project', $claims, []);

        $this->assertEquals('user-123', $token->getClaim('user_id'));
        $this->assertEquals('value', $token->getClaim('custom_claim'));
        $this->assertEquals(['key' => 'value'], $token->getClaim('nested'));
        $this->assertNull($token->getClaim('non_existent'));
        $this->assertEquals('default', $token->getClaim('non_existent', 'default'));
    }

    public function testGetUserId(): void
    {
        $token1 = new OctowireToken('token', 'project', ['user_id' => 'user-123'], []);
        $this->assertEquals('user-123', $token1->getUserId());

        $token2 = new OctowireToken('token', 'project', ['sub' => 'user-456'], []);
        $this->assertEquals('user-456', $token2->getUserId());

        $token3 = new OctowireToken('token', 'project', [], []);
        $this->assertNull($token3->getUserId());
    }

    public function testGetCredentials(): void
    {
        $jwtToken = 'test.jwt.token';
        $token = new OctowireToken($jwtToken, 'project', [], []);

        $this->assertEquals($jwtToken, $token->getCredentials());
    }

    public function testTokenWithUser(): void
    {
        $user = OctowireUser::fromClaims(['user_id' => 'user-123', 'role' => 'admin']);
        $token = new OctowireToken('token', 'project', ['user_id' => 'user-123'], ['ROLE_USER']);
        $token->setUser($user);

        $this->assertEquals($user, $token->getUser());
    }

    public function testTokenNullProjectId(): void
    {
        $token = new OctowireToken('token', null, [], []);

        $this->assertNull($token->getProjectId());
    }
}

