<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Unit\Security;

use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireUser;
use PHPUnit\Framework\TestCase;

class OctowireUserTest extends TestCase
{
    public function testUserCreation(): void
    {
        $userId = 'user-123';
        $claims = ['custom' => 'value'];
        $roles = ['ROLE_USER', 'ROLE_ADMIN'];

        $user = new OctowireUser($userId, $claims, $roles);

        $this->assertEquals($userId, $user->getUserIdentifier());
        $this->assertEquals($userId, $user->getUserId());
        $this->assertEquals($claims, $user->getClaims());
        $this->assertEquals($roles, $user->getRoles());
    }

    public function testFromClaimsWithUserId(): void
    {
        $claims = [
            'user_id' => 'user-123',
            'role' => 'admin',
            'custom' => 'value',
        ];

        $user = OctowireUser::fromClaims($claims);

        $this->assertEquals('user-123', $user->getUserId());
        $this->assertContains('ROLE_ADMIN', $user->getRoles());
        // ROLE_USER is only added if no roles are found - here we have ROLE_ADMIN
        $this->assertNotContains('ROLE_USER', $user->getRoles());
        $this->assertEquals('value', $user->getClaim('custom'));
    }

    public function testFromClaimsWithSub(): void
    {
        $claims = [
            'sub' => 'user-456',
            'roles' => ['user', 'manager'],
        ];

        $user = OctowireUser::fromClaims($claims);

        $this->assertEquals('user-456', $user->getUserId());
        $this->assertContains('ROLE_USER', $user->getRoles());
        $this->assertContains('ROLE_MANAGER', $user->getRoles());
    }

    public function testFromClaimsDefaultRole(): void
    {
        $claims = ['user_id' => 'user-789'];

        $user = OctowireUser::fromClaims($claims);

        $this->assertContains('ROLE_USER', $user->getRoles());
        $this->assertCount(1, $user->getRoles());
    }

    public function testGetClaim(): void
    {
        $claims = [
            'user_id' => 'user-123',
            'nested' => ['key' => 'value'],
            'number' => 42,
        ];

        $user = new OctowireUser('user-123', $claims);

        $this->assertEquals('user-123', $user->getClaim('user_id'));
        $this->assertEquals(['key' => 'value'], $user->getClaim('nested'));
        $this->assertEquals(42, $user->getClaim('number'));
        $this->assertNull($user->getClaim('non_existent'));
        $this->assertEquals('default', $user->getClaim('non_existent', 'default'));
    }

    public function testRolesExtractionWithArray(): void
    {
        $claims = [
            'user_id' => 'user-123',
            'roles' => ['admin', 'user', 'manager'],
        ];

        $user = OctowireUser::fromClaims($claims);

        $this->assertContains('ROLE_ADMIN', $user->getRoles());
        $this->assertContains('ROLE_USER', $user->getRoles());
        $this->assertContains('ROLE_MANAGER', $user->getRoles());
    }

    public function testRolesExtractionWithSingleRole(): void
    {
        $claims = [
            'user_id' => 'user-123',
            'role' => 'admin',
        ];

        $user = OctowireUser::fromClaims($claims);

        $this->assertContains('ROLE_ADMIN', $user->getRoles());
        // ROLE_USER is only added if no roles are found - here we have ROLE_ADMIN
        $this->assertNotContains('ROLE_USER', $user->getRoles());
    }

    public function testRolesPrefixNormalization(): void
    {
        $claims = [
            'user_id' => 'user-123',
            'role' => 'ADMIN', // Already uppercase
        ];

        $user = OctowireUser::fromClaims($claims);

        $this->assertContains('ROLE_ADMIN', $user->getRoles());
        $this->assertNotContains('ADMIN', $user->getRoles());
    }

    public function testEraseCredentials(): void
    {
        $user = new OctowireUser('user-123', []);

        // Should not throw exception
        $user->eraseCredentials();

        $this->assertTrue(true);
    }

    public function testFromClaimsWithProvidedRoles(): void
    {
        $claims = ['user_id' => 'user-123'];
        $roles = ['ROLE_CUSTOM'];

        $user = OctowireUser::fromClaims($claims, $roles);

        $this->assertEquals($roles, $user->getRoles());
    }
}

