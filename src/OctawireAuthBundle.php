<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle;

use Kabiroman\Octawire\AuthService\Bundle\DependencyInjection\OctawireAuthExtension;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Octawire Auth Service Bundle
 *
 * Symfony Bundle for integrating Octawire Auth Service PHP Client
 * with Symfony Security Component.
 */
class OctawireAuthBundle extends Bundle
{
    /**
     * {@inheritdoc}
     */
    public function getContainerExtension(): ?\Symfony\Component\DependencyInjection\Extension\ExtensionInterface
    {
        return new OctawireAuthExtension();
    }
}

