<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Security;

use Kabiroman\Octawire\AuthService\Bundle\Service\TokenValidator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * Authenticator for JWT tokens from Octawire Auth Service
 */
class OctowireTokenAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    private TokenValidator $tokenValidator;
    private ?string $defaultProjectId;
    private ?string $currentToken = null;

    public function __construct(TokenValidator $tokenValidator, ?string $defaultProjectId = null)
    {
        $this->tokenValidator = $tokenValidator;
        $this->defaultProjectId = $defaultProjectId;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization') &&
               str_starts_with($request->headers->get('Authorization', ''), 'Bearer ');
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(Request $request): Passport
    {
        $token = $this->extractToken($request);

        if (empty($token)) {
            throw new BadCredentialsException('Token not found in Authorization header.');
        }

        // Store token for use in createToken
        $this->currentToken = $token;

        // Try to extract project_id from token, fallback to default
        $projectId = $this->tokenValidator->extractProjectIdFromToken($token) ?? $this->defaultProjectId;

        // Validate token
        $validationResponse = $this->tokenValidator->validateToken($token, $projectId);

        // Extract claims
        $claims = $validationResponse['claims'] ?? [];
        $userId = $claims['user_id'] ?? $claims['sub'] ?? '';

        if (empty($userId)) {
            throw new BadCredentialsException('User ID not found in token claims.');
        }

        // Create user from claims
        $user = OctowireUser::fromClaims($claims);

        return new SelfValidatingPassport(
            new UserBadge($userId, function () use ($user) {
                return $user;
            })
        );
    }

    /**
     * {@inheritdoc}
     */
    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        $user = $passport->getUser();
        if (!$user instanceof OctowireUser) {
            throw new \LogicException('User must be an instance of OctowireUser.');
        }

        $claims = $user->getClaims();
        $jwtToken = $this->currentToken ?? '';

        // Try to extract project_id from token, fallback to default
        $projectId = $this->tokenValidator->extractProjectIdFromToken($jwtToken) ?? $this->defaultProjectId;

        $token = new OctowireToken($jwtToken, $projectId, $claims, $user->getRoles());
        $token->setUser($user);

        // Clear stored token
        $this->currentToken = null;

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        // Return null to continue the request
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new JsonResponse([
            'error' => 'Authentication failed',
            'message' => $exception->getMessage(),
        ], Response::HTTP_UNAUTHORIZED);
    }

    /**
     * {@inheritdoc}
     */
    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return new JsonResponse([
            'error' => 'Authentication required',
            'message' => 'JWT token is required in Authorization header (Bearer token)',
        ], Response::HTTP_UNAUTHORIZED);
    }

    /**
     * Extract JWT token from Authorization header
     */
    private function extractToken(Request $request): ?string
    {
        $authorization = $request->headers->get('Authorization', '');

        if (empty($authorization) || !str_starts_with($authorization, 'Bearer ')) {
            return null;
        }

        return trim(substr($authorization, 7));
    }
}

