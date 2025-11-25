<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Security;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * User Provider for OctowireUser
 *
 * This provider is used by Symfony Security to reload users from session.
 * Since we use stateless JWT authentication, this is mainly for compatibility.
 */
class OctowireUserProvider implements UserProviderInterface
{
    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof OctowireUser) {
            throw new UnsupportedUserException(sprintf('Invalid user class "%s".', get_class($user)));
        }

        // For stateless JWT authentication, we can't refresh the user
        // The token should be re-validated on each request
        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass(string $class): bool
    {
        return OctowireUser::class === $class;
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        // This method is called when loading user from session
        // For stateless JWT, we should not rely on this
        throw new UserNotFoundException('User cannot be loaded by identifier in stateless JWT authentication.');
    }
}




