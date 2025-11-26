<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Service\Cache;

/**
 * Default in-memory cache implementation for public keys.
 */
class InMemoryKeyCache implements KeyCacheInterface
{
    /**
     * @var array<string, array{key: string, expires: int}>
     */
    private array $storage = [];

    public function get(string $key): ?array
    {
        return $this->storage[$key] ?? null;
    }

    public function set(string $key, string $publicKey, int $expiresAt): void
    {
        $this->storage[$key] = [
            'key' => $publicKey,
            'expires' => $expiresAt,
        ];
    }

    public function delete(string $key): void
    {
        unset($this->storage[$key]);
    }
}

