#!/usr/bin/env php
<?php
/**
 * HTTP Integration Test Example
 * 
 * Tests the full Symfony authentication flow:
 * 1. Issue token via AuthClient
 * 2. Make HTTP requests to Symfony endpoints with token
 * 3. Verify authentication and user data extraction
 * 
 * Requirements:
 * - Auth Service running on localhost:50052 (TCP/JATP)
 * - Symfony application running on localhost:8000
 * - Bundle configured in Symfony app
 * 
 * Usage:
 *   php test-http-integration.php [symfony_url]
 * 
 * Example:
 *   php test-http-integration.php http://localhost:8000
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
use Kabiroman\Octawire\AuthService\Client\Request\JWT\IssueTokenRequest;

echo "=== HTTP Integration Test for Symfony Bundle ===\n";
echo "Bundle Version: 0.9.4 (Protocol v1.0)\n\n";

// =============================================================================
// CONFIGURATION
// =============================================================================

$symfonyBaseUrl = $argv[1] ?? getenv('SYMFONY_URL') ?: 'http://localhost:8000';

$authServiceConfig = [
    'transport' => 'tcp',
    'tcp' => [
        'host' => getenv('AUTH_SERVICE_HOST') ?: 'localhost',
        'port' => (int)(getenv('AUTH_SERVICE_PORT') ?: 50052),
        'tls' => ['enabled' => (bool)(getenv('AUTH_SERVICE_TLS') ?: false)],
    ],
];

$projectId = getenv('AUTH_SERVICE_PROJECT_ID') ?: 'test-project-id';
$testUserId = 'http-test-user-' . uniqid();

echo "Configuration:\n";
echo "  Symfony URL: {$symfonyBaseUrl}\n";
echo "  Auth Service: {$authServiceConfig['tcp']['host']}:{$authServiceConfig['tcp']['port']}\n";
echo "  Project ID: {$projectId}\n\n";

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Make HTTP request using curl
 */
function httpRequest(string $method, string $url, array $headers = []): array {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    
    $headerStrings = [];
    foreach ($headers as $name => $value) {
        $headerStrings[] = "$name: $value";
    }
    if (!empty($headerStrings)) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headerStrings);
    }
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    return [
        'status' => $httpCode,
        'body' => $response,
        'error' => $error,
    ];
}

// =============================================================================
// STEP 1: CREATE CLIENT AND ISSUE TOKEN
// =============================================================================

try {
    $config = new Config($authServiceConfig);
    $client = new AuthClient($config);
    echo "✓ AuthClient created\n";
} catch (\Exception $e) {
    echo "✗ Failed to create AuthClient: " . $e->getMessage() . "\n";
    exit(1);
}

echo "\n--- Step 1: Issue Token ---\n";
try {
    $issueRequest = new IssueTokenRequest(
        userId: $testUserId,
        projectId: $projectId,
        claims: ['role' => 'admin', 'custom_claim' => 'test_value'],
        accessTokenTtl: 3600,
        refreshTokenTtl: 86400
    );
    
    $tokenResponse = $client->issueToken($issueRequest);
    $accessToken = $tokenResponse->accessToken;
    
    echo "✓ Token issued: " . substr($accessToken, 0, 50) . "...\n";
} catch (\Exception $e) {
    echo "✗ Failed to issue token: " . $e->getMessage() . "\n";
    exit(1);
}

// =============================================================================
// STEP 2: TEST HTTP ENDPOINTS
// =============================================================================

echo "\n--- Step 2: Test HTTP Endpoints ---\n";

// Define test endpoints - adjust paths to match your Symfony routes
$testEndpoints = [
    [
        'name' => 'Public endpoint (no auth)',
        'path' => '/test/public',
        'auth' => false,
        'expectedStatus' => 200,
    ],
    [
        'name' => 'Protected endpoint (no auth - should fail)',
        'path' => '/test/protected',
        'auth' => false,
        'expectedStatus' => 401,
    ],
    [
        'name' => 'Protected endpoint (with valid token)',
        'path' => '/test/protected',
        'auth' => true,
        'expectedStatus' => 200,
    ],
    [
        'name' => 'User info endpoint (with valid token)',
        'path' => '/test/user-info',
        'auth' => true,
        'expectedStatus' => 200,
    ],
];

$testsPassed = 0;
$testsFailed = 0;

foreach ($testEndpoints as $index => $test) {
    $testNum = $index + 1;
    echo "\n[Test 2.{$testNum}] {$test['name']}:\n";
    
    $headers = [];
    if ($test['auth']) {
        $headers['Authorization'] = 'Bearer ' . $accessToken;
    }
    
    $result = httpRequest('GET', $symfonyBaseUrl . $test['path'], $headers);
    
    if ($result['error']) {
        echo "  ✗ Connection error: {$result['error']}\n";
        echo "  Note: Make sure Symfony server is running at {$symfonyBaseUrl}\n";
        $testsFailed++;
        continue;
    }
    
    $content = json_decode($result['body'], true);
    echo "  Status: {$result['status']}\n";
    
    if ($content !== null) {
        echo "  Response: " . json_encode($content, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
    }
    
    if ($result['status'] === $test['expectedStatus']) {
        echo "  ✓ Test passed (expected status {$test['expectedStatus']})\n";
        $testsPassed++;
        
        // Additional checks for authenticated endpoints
        if ($test['auth'] && $result['status'] === 200) {
            // Check for user data in response
            if (isset($content['user']['id'])) {
                echo "  ✓ User ID extracted: {$content['user']['id']}\n";
            }
            if (isset($content['user']['roles'])) {
                echo "  ✓ Roles extracted: " . json_encode($content['user']['roles']) . "\n";
            }
            // Check for camelCase claims (v0.9.4+)
            if (isset($content['all_claims']['userId']) || isset($content['user']['claims']['userId'])) {
                echo "  ✓ Using camelCase 'userId' field (v0.9.4+)\n";
            }
        }
    } else {
        echo "  ✗ Test failed (expected {$test['expectedStatus']}, got {$result['status']})\n";
        $testsFailed++;
    }
}

// =============================================================================
// SUMMARY
// =============================================================================

echo "\n=== Test Summary ===\n";
echo "Passed: {$testsPassed}\n";
echo "Failed: {$testsFailed}\n";

if ($testsFailed > 0) {
    echo "\n⚠️  Some tests failed. Check:\n";
    echo "  1. Is Symfony server running at {$symfonyBaseUrl}?\n";
    echo "  2. Is Auth Service running on port {$authServiceConfig['tcp']['port']}?\n";
    echo "  3. Does project_id '{$projectId}' match Auth Service config?\n";
    echo "  4. Are the test endpoints (/test/public, /test/protected, etc.) defined?\n";
    exit(1);
}

echo "\n✅ All HTTP integration tests passed!\n";
echo "\nUseful commands:\n";
echo "  # Start Symfony dev server:\n";
echo "  symfony server:start --port=8000\n";
echo "  # Or with PHP built-in server:\n";
echo "  php -S localhost:8000 -t public\n";

