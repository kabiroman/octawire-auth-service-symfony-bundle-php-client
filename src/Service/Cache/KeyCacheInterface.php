<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Service\Cache;

/**
 * Simple cache interface for local public keys
 */
interface KeyCacheInterface
{
    /**
     * @return array{key: string, expires: int}|null
     */
    public function get(string $key): ?array;

    public function set(string $key, string $publicKey, int $expiresAt): void;

    public function delete(string $key): void;
}

