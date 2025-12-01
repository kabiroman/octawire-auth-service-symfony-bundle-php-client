#!/usr/bin/env php
<?php
/**
 * Client Integration Test Example
 * 
 * Tests direct communication with Auth Service via PHP Client (without Symfony).
 * Use this to verify that Auth Service is running and responding correctly.
 * 
 * Requirements:
 * - Auth Service running on localhost:50052 (TCP/JATP)
 * - composer install in your Symfony project
 * 
 * Usage:
 *   php test-client-integration.php
 * 
 * Configuration:
 *   Modify $config array below to match your Auth Service settings.
 * 
 * @package Kabiroman\Octawire\AuthService\Bundle
 * @version 0.9.4
 */

// Adjust autoloader path based on your project structure
$autoloadPaths = [
    __DIR__ . '/../../vendor/autoload.php',      // From examples/ in bundle
    __DIR__ . '/../vendor/autoload.php',          // From project root
    __DIR__ . '/vendor/autoload.php',             // Current directory
];

$autoloaded = false;
foreach ($autoloadPaths as $path) {
    if (file_exists($path)) {
        require_once $path;
        $autoloaded = true;
        break;
    }
}

if (!$autoloaded) {
    echo "Error: Cannot find autoload.php. Run 'composer install' first.\n";
    exit(1);
}

use Kabiroman\Octawire\AuthService\Client\AuthClient;
use Kabiroman\Octawire\AuthService\Client\Config;
use Kabiroman\Octawire\AuthService\Client\Request\JWT\HealthCheckRequest;
use Kabiroman\Octawire\AuthService\Client\Request\JWT\IssueTokenRequest;
use Kabiroman\Octawire\AuthService\Client\Request\JWT\ValidateTokenRequest;
use Kabiroman\Octawire\AuthService\Client\Exception\AuthException;

echo "=== Auth Service Client Integration Test ===\n";
echo "Bundle Version: 0.9.4 (Protocol v1.0)\n\n";

// =============================================================================
// CONFIGURATION - Modify these settings to match your Auth Service
// =============================================================================

$config = [
    'transport' => 'tcp',
    'tcp' => [
        'host' => getenv('AUTH_SERVICE_HOST') ?: 'localhost',
        'port' => (int)(getenv('AUTH_SERVICE_PORT') ?: 50052),
        'persistent' => false,
        'tls' => [
            'enabled' => (bool)(getenv('AUTH_SERVICE_TLS') ?: false),
            // Uncomment for TLS:
            // 'ca_file' => '/path/to/ca.crt',
            // 'cert_file' => '/path/to/client.crt',
            // 'key_file' => '/path/to/client.key',
            // 'server_name' => 'localhost',
        ],
    ],
    'timeout' => [
        'connect' => 10.0,
        'request' => 30.0,
    ],
];

// Project ID must match Auth Service configuration
$projectId = getenv('AUTH_SERVICE_PROJECT_ID') ?: 'test-project-id';
$testUserId = 'test-user-' . uniqid();

// =============================================================================
// TESTS
// =============================================================================

try {
    $clientConfig = new Config($config);
    $client = new AuthClient($clientConfig);
    echo "✓ AuthClient created\n";
    echo "  Host: {$config['tcp']['host']}:{$config['tcp']['port']}\n";
    echo "  TLS: " . ($config['tcp']['tls']['enabled'] ? 'enabled' : 'disabled') . "\n\n";
} catch (\Exception $e) {
    echo "✗ Failed to create AuthClient: " . $e->getMessage() . "\n";
    exit(1);
}

// -----------------------------------------------------------------------------
// Test 1: Health Check
// -----------------------------------------------------------------------------
echo "--- Test 1: Health Check ---\n";
try {
    $healthResponse = $client->healthCheck(new HealthCheckRequest());
    
    // v0.9.4: status field (string) instead of healthy (bool)
    // Accept 'healthy' or 'degraded' (degraded is OK in dev - e.g. Redis issues)
    if (in_array($healthResponse->status, ['healthy', 'degraded'])) {
        echo "✓ Health check passed\n";
        echo "  Status: {$healthResponse->status}\n";
        if ($healthResponse->version) {
            echo "  Version: {$healthResponse->version}\n";
        }
        if ($healthResponse->timestamp) {
            echo "  Timestamp: " . date('Y-m-d H:i:s', $healthResponse->timestamp) . "\n";
        }
    } else {
        echo "✗ Health check failed: Status is '{$healthResponse->status}'\n";
        exit(1);
    }
} catch (AuthException $e) {
    echo "✗ Health check failed: " . $e->getMessage() . "\n";
    echo "  Error code: " . $e->getErrorCode() . "\n";
    exit(1);
} catch (\Exception $e) {
    echo "✗ Health check failed: " . $e->getMessage() . "\n";
    exit(1);
}

// -----------------------------------------------------------------------------
// Test 2: Issue Token
// -----------------------------------------------------------------------------
echo "\n--- Test 2: Issue Token ---\n";
$accessToken = null;
try {
    $issueRequest = new IssueTokenRequest(
        userId: $testUserId,
        projectId: $projectId,
        claims: ['role' => 'admin', 'custom_claim' => 'test_value'],
        accessTokenTtl: 3600,
        refreshTokenTtl: 86400
    );
    
    $tokenResponse = $client->issueToken($issueRequest);
    
    if (!empty($tokenResponse->accessToken)) {
        echo "✓ Token issued successfully\n";
        echo "  Access Token: " . substr($tokenResponse->accessToken, 0, 50) . "...\n";
        echo "  Refresh Token: " . substr($tokenResponse->refreshToken, 0, 50) . "...\n";
        // v0.9.4: expiresIn (seconds) instead of accessTokenExpiresAt (timestamp)
        echo "  Expires In: {$tokenResponse->expiresIn} seconds\n";
        $accessToken = $tokenResponse->accessToken;
    } else {
        echo "✗ Token response is empty\n";
        exit(1);
    }
} catch (AuthException $e) {
    echo "✗ Issue token failed: " . $e->getMessage() . "\n";
    echo "  Error code: " . $e->getErrorCode() . "\n";
    exit(1);
} catch (\Exception $e) {
    echo "✗ Issue token failed: " . $e->getMessage() . "\n";
    exit(1);
}

// -----------------------------------------------------------------------------
// Test 3: Validate Token
// -----------------------------------------------------------------------------
echo "\n--- Test 3: Validate Token ---\n";
if ($accessToken) {
    try {
        $validateRequest = new ValidateTokenRequest(
            token: $accessToken,
            projectId: $projectId,  // Required in v0.9.3+
            checkBlacklist: true
        );
        
        $validateResponse = $client->validateToken($validateRequest);
        
        if ($validateResponse->valid) {
            echo "✓ Token validated successfully\n";
            if ($validateResponse->claims) {
                $claims = $validateResponse->claims;
                // v0.9.4: uses camelCase field names
                echo "  User ID: {$claims->userId}\n";
                echo "  Token Type: {$claims->tokenType}\n";
                echo "  Issuer: {$claims->issuer}\n";
                echo "  Audience: {$claims->audience}\n";
                echo "  Custom Claims: " . json_encode($claims->customClaims) . "\n";
            }
        } else {
            echo "✗ Token validation failed: " . ($validateResponse->error ?? 'Unknown error') . "\n";
            exit(1);
        }
    } catch (AuthException $e) {
        echo "✗ Validate token failed: " . $e->getMessage() . "\n";
        echo "  Error code: " . $e->getErrorCode() . "\n";
        exit(1);
    } catch (\Exception $e) {
        echo "✗ Validate token failed: " . $e->getMessage() . "\n";
        exit(1);
    }
}

// -----------------------------------------------------------------------------
// Test 4: Token Structure Verification
// -----------------------------------------------------------------------------
echo "\n--- Test 4: Token Structure (for Bundle compatibility) ---\n";
try {
    $parts = explode('.', $accessToken);
    if (count($parts) === 3) {
        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
        echo "✓ Token payload parsed\n";
        
        // v0.9.4+: Check for camelCase fields
        $projectIdValue = $payload['projectId'] ?? $payload['project_id'] ?? $payload['aud'] ?? null;
        echo "  Project ID: " . ($projectIdValue ?? 'not found') . "\n";
        
        $userIdValue = $payload['userId'] ?? $payload['user_id'] ?? $payload['sub'] ?? null;
        echo "  User ID: " . ($userIdValue ?? 'not found') . "\n";
        
        if (isset($payload['role'])) {
            echo "  Role: {$payload['role']}\n";
        }
        if (isset($payload['custom_claim'])) {
            echo "  Custom Claim: {$payload['custom_claim']}\n";
        }
    }
} catch (\Exception $e) {
    echo "✗ Token parsing failed: " . $e->getMessage() . "\n";
}

// =============================================================================
// SUMMARY
// =============================================================================
echo "\n=== All tests passed! ===\n";
echo "\nAuth Service is ready for Bundle integration.\n";
echo "You can use this token for HTTP testing:\n";
echo "  Authorization: Bearer " . substr($accessToken, 0, 60) . "...\n";
echo "\nEnvironment variables:\n";
echo "  AUTH_SERVICE_HOST={$config['tcp']['host']}\n";
echo "  AUTH_SERVICE_PORT={$config['tcp']['port']}\n";
echo "  AUTH_SERVICE_PROJECT_ID={$projectId}\n";

