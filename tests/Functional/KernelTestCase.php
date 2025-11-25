<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Functional;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase as BaseKernelTestCase;
use Symfony\Component\HttpKernel\KernelInterface;
use Kabiroman\Octawire\AuthService\Bundle\Tests\Fixtures\TestKernel;

abstract class KernelTestCase extends BaseKernelTestCase
{
    protected static function getKernelClass(): string
    {
        return TestKernel::class;
    }

    protected static function createKernel(array $options = []): KernelInterface
    {
        return new TestKernel(
            $options['environment'] ?? 'test',
            $options['debug'] ?? true,
            $options['test_case'] ?? null
        );
    }
}

