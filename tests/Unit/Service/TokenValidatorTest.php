<?php

declare(strict_types=1);

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Unit\Service;

use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;
use Kabiroman\Octawire\AuthService\Bundle\Service\TokenValidator;
use PHPUnit\Framework\TestCase;

class TokenValidatorTest extends TestCase
{
    private AuthClientFactory $clientFactory;
    private TokenValidator $tokenValidator;

    protected function setUp(): void
    {
        $this->clientFactory = $this->createMock(AuthClientFactory::class);
        $this->tokenValidator = new TokenValidator($this->clientFactory);
    }

    public function testExtractProjectIdFromTokenReturnsNullForInvalidToken(): void
    {
        $result = $this->tokenValidator->extractProjectIdFromToken('invalid-token');
        $this->assertNull($result);
    }

    public function testExtractProjectIdFromTokenReturnsNullForEmptyToken(): void
    {
        $result = $this->tokenValidator->extractProjectIdFromToken('');
        $this->assertNull($result);
    }
}




