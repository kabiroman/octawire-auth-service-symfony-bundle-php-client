# Руководство по тестированию Octawire Auth Service Symfony Bundle

Документ описывает всю процедуру проверки бандла: от локальных юнит‑тестов до интеграционных прогонов с запущенным Go‑сервисом.

## Quick Start: Integration Testing

Для быстрой проверки работоспособности Bundle с реальным Auth Service используйте примеры из `examples/integration-tests/`:

```bash
# 1. Запустить Auth Service (без TLS, без auth)
cd /path/to/services/auth-service
./auth-service --config config/config.test.local.json

# 2. Запустить тест клиента (проверка подключения к Auth Service)
cd /path/to/your/symfony-project
php vendor/kabiroman/octawire-auth-service-php-client-bundle/examples/integration-tests/test-client-integration.php

# 3. Запустить Symfony приложение
symfony server:start --port=8000

# 4. Запустить HTTP тест (проверка аутентификации)
php vendor/kabiroman/octawire-auth-service-php-client-bundle/examples/integration-tests/test-http-integration.php
```

Подробнее: [`examples/integration-tests/README.md`](examples/integration-tests/README.md)

---

## 1. Предварительные условия

| Компонент | Требования |
| --- | --- |
| PHP | 8.2+ (с расширениями `ext-json`, `ext-sockets`) |
| Composer | 2.x |
| OpenSSL | для генерации TLS‑сертификатов |
| Go Auth Service | Собранный бинарь `services/auth-service/bin/auth-service` |
| Redis | используется Auth Service (см. `config/config.json`) |

Дополнительно:

1. Склонирован репозиторий `octawire`.
2. В каталоге `services/auth-service/clients/php/bundle` выполнено `composer install`.
3. В корне `services/auth-service` собран и настроен Go‑сервис (см. README + Makefile).

## 2. Юнит‑ и функциональные тесты бандла

### 2.1 Установка зависимостей

```bash
cd services/auth-service/clients/php/bundle
composer install
```

### 2.2 Запуск всех тестов

```bash
vendor/bin/phpunit
```

Структура тестов:

- `tests/Unit/...` — изолированные проверки (TokenValidator, LocalTokenValidator, AuthClientFactory и т.д.).
- `tests/Functional/...` — минимальные Symfony‑Kernel тесты (конфигурация бандла, DI‑регистрация, security интеграция).  
  Для них используется тестовый kernel в `tests/Fixtures`.

### 2.3 Частичный запуск

```bash
# только unit
vendor/bin/phpunit --testsuite unit

# конкретный тест
vendor/bin/phpunit tests/Unit/Service/TokenValidatorTest.php
```

## 3. Интеграционные тесты на otus_project2

### 3.1 Линковка бандла как path‑репозитория

В `services/auth-service/clients/php/otus_project2/composer.json` уже прописан:

```json
"repositories": [
  {
    "type": "path",
    "url": "../bundle",
    "options": {
      "symlink": true,
      "canonical": false
    }
  }
]
```

Достаточно один раз выполнить:

```bash
cd services/auth-service/clients/php/otus_project2
composer install
```

### 3.2 Запуск Auth Service

1. Перейти в `services/auth-service`.
2. Убедиться, что `config/config.json` содержит:
   - включённый TCP‑порт 50052;
   - TLS с dev‑сертификатами (`config/tls/server.crt` etc.);
   - `security.service_auth.enabled = true` и заданы `secrets` / `allowed_services`.
3. Запустить сервис:

```bash
./bin/auth-service --config config/config.json
```

> В текущей версии сервер **не проверяет** корректность `service_secret`. Это известная проблема (см. `docs/KNOWN_ISSUES.md`), из‑за которой один интеграционный тест помечен `markTestSkipped`.

### 3.3 TLS/мTLS артефакты для клиента

В `otus_project2/config/tls/` уже лежат `dev-ca.crt`, `client.crt`, `client.key`. Они используются во всех тестовых окружениях.

### 3.4 Конфигурации окружений

Файлы находятся в `config/packages/`:

| Файл | Назначение |
| --- | --- |
| `tests/config/packages/test/octawire_auth.yaml` | Основная конфигурация (TLS + рабочие креды) |
| `.../test_invalid_secret/octawire_auth.yaml` | Uses wrong `service_secret` (тест пока пропущен из‑за бага сервера) |
| `.../test_wrong_tls/octawire_auth.yaml` | Указывает невалидный CA для проверки TLS ошибок |

### 3.5 Запуск интеграционных тестов

```bash
cd services/auth-service/clients/php/otus_project2
./bin/phpunit tests/Integration/BundleIntegrationTest.php
```

Покрываемые сценарии:

1. Публичные/защищённые роуты (`/test/public`, `/test/protected`, `/test/admin`).
2. Успешная аутентификация и авторизация (извлечение claims, роль ADMIN).
3. Неверный токен и отсутствие токена.
4. `project_id` whitelist — токен с неразрешённым `project_id` должен дать 401.
5. TLS‑ошибки при неправильном CA.
6. Сервисная аутентификация (позитивный сценарий). Негативный кейс временно пропущен (см. выше).

Вывод PHPUnit будет содержать 1 skipped‑тест, пока сервер не начнёт отклонять неверные `service_secret`.

## 4. Частые проблемы

| Симптом | Решение |
| --- | --- |
| `Class ...\KernelTestCase not found` при запуске тестов бандла | Выполните `composer install` в каталоге бандла — тестовый kernel находится в `tests/Fixtures`. |
| `Connection closed by server` / `Failed to connect to localhost:50052` | Проверьте, что Auth Service запущен, порт 50052 свободен, TLS в конфиге клиента указывает на корректные файлы. |
| `service auth failed` | Причина — Auth Service не поднят или не принимает соединение (таймаут). В текущей версии неверные секреты не распознаются. |

## 5. Примеры конфигурации и кода

### 5.1 Конфигурация бандла (`config/packages/octawire_auth.yaml`)

Базовая конфигурация с TLS и service auth:

```yaml
octawire_auth:
    default_project: 'test-project'
    projects:
        test-project:
            transport: 'tcp'
            tcp:
                host: 'localhost'
                port: 50052
                persistent: true
                tls:
                    enabled: true
                    required: true
                    ca_file: '%kernel.project_dir%/config/tls/dev-ca.crt'
                    cert_file: '%kernel.project_dir%/config/tls/client.crt'
                    key_file: '%kernel.project_dir%/config/tls/client.key'
                    server_name: 'localhost'
            project_id: 'test-project'
            service_auth:
                service_name: 'test-service'
                service_secret: 'test-service-secret-123'
            retry:
                max_attempts: 3
                initial_backoff: 0.1
                max_backoff: 5.0
            key_cache:
                driver: 'memory'
                ttl: 3600
                max_size: 100
            timeout:
                connect: 10.0
                request: 30.0
        admin-project:
            transport: 'tcp'
            tcp:
                host: 'localhost'
                port: 50052
                persistent: true
                tls:
                    enabled: true
                    required: true
                    ca_file: '%kernel.project_dir%/config/tls/dev-ca.crt'
                    cert_file: '%kernel.project_dir%/config/tls/client.crt'
                    key_file: '%kernel.project_dir%/config/tls/client.key'
                    server_name: 'localhost'
            project_id: 'admin-project'
            service_auth:
                service_name: 'internal-api'
                service_secret: 'internal-api-secret-789'
            retry:
                max_attempts: 3
            key_cache:
                driver: 'memory'
                ttl: 3600
```

### 5.2 Конфигурация Security (`config/packages/security.yaml`)

```yaml
security:
    password_hashers:
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface: 'auto'

    providers:
        octawire_user_provider:
            id: octawire_auth.user_provider

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        test:
            pattern: ^/test
            stateless: true
            custom_authenticators:
                - octawire_auth.authenticator
            provider: octawire_user_provider

    access_control:
        - { path: ^/test/public, roles: PUBLIC_ACCESS }
        - { path: ^/test/protected, roles: ROLE_USER }
        - { path: ^/test/admin, roles: ROLE_ADMIN }
        - { path: ^/test, roles: ROLE_USER }

    role_hierarchy:
        ROLE_ADMIN: ROLE_USER
```

### 5.3 Пример контроллера

```php
<?php

namespace App\Controller;

use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireUser;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class TestController extends AbstractController
{
    #[Route('/test/public', name: 'test_public', methods: ['GET'])]
    public function public(): JsonResponse
    {
        return new JsonResponse([
            'message' => 'This is a public endpoint',
            'user' => $this->getUser() ? 'authenticated' : 'anonymous',
        ]);
    }

    #[Route('/test/protected', name: 'test_protected', methods: ['GET'])]
    #[IsGranted('ROLE_USER')]
    public function protected(): JsonResponse
    {
        $user = $this->getUser();

        return new JsonResponse([
            'message' => 'This is a protected endpoint',
            'user' => $user instanceof OctowireUser ? [
                'id' => $user->getUserId(),
                'identifier' => $user->getUserIdentifier(),
                'roles' => $user->getRoles(),
                'claims' => $user->getClaims(),
            ] : null,
        ]);
    }

    #[Route('/test/admin', name: 'test_admin', methods: ['GET'])]
    #[IsGranted('ROLE_ADMIN')]
    public function admin(): JsonResponse
    {
        $user = $this->getUser();

        return new JsonResponse([
            'message' => 'This is an admin endpoint',
            'user' => $user instanceof OctowireUser ? [
                'id' => $user->getUserId(),
                'roles' => $user->getRoles(),
            ] : null,
        ]);
    }

    #[Route('/test/user-info', name: 'test_user_info', methods: ['GET'])]
    #[IsGranted('ROLE_USER')]
    public function userInfo(): JsonResponse
    {
        $user = $this->getUser();

        if (!$user instanceof OctowireUser) {
            return new JsonResponse(['error' => 'User not found'], 401);
        }

        return new JsonResponse([
            'user_id' => $user->getUserId(),
            'user_identifier' => $user->getUserIdentifier(),
            'roles' => $user->getRoles(),
            'all_claims' => $user->getClaims(),
            'custom_claim' => $user->getClaim('custom', 'not_found'),
        ]);
    }
}
```

### 5.4 Пример интеграционного теста

```php
<?php

namespace App\Tests\Integration;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

class BundleIntegrationTest extends WebTestCase
{
    private ?string $testToken = null;

    protected function setUp(): void
    {
        parent::setUp();
        // Выпуск тестового токена через AuthClient
        $this->testToken = $this->issueTestToken();
    }

    public function testProtectedEndpointWithValidToken(): void
    {
        if (!$this->testToken) {
            $this->markTestSkipped('No test token available');
        }

        $client = static::createClient();
        $client->request('GET', '/test/protected', [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $this->testToken,
        ]);

        $this->assertResponseIsSuccessful();
        $response = json_decode($client->getResponse()->getContent(), true);
        $this->assertArrayHasKey('user', $response);
        $this->assertNotNull($response['user']);
    }

    public function testAdminEndpointWithAdminProjectToken(): void
    {
        $adminToken = $this->issueTokenForProject('admin-project', [
            'role' => 'ROLE_ADMIN',
            'email' => 'admin@example.com',
        ]);

        if (!$adminToken) {
            $this->markTestSkipped('Could not issue admin project token');
        }

        $client = static::createClient();
        $client->request('GET', '/test/admin', [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $adminToken,
        ]);

        $this->assertResponseIsSuccessful();
    }

    public function testProtectedEndpointRejectsUnlistedProjectToken(): void
    {
        $foreignToken = $this->issueTokenForProject('unlisted-project', [
            'role' => 'user',
        ]);

        if (!$foreignToken) {
            $this->markTestSkipped('Could not issue token for unlisted project');
        }

        $client = static::createClient();
        $client->request('GET', '/test/protected', [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $foreignToken,
        ]);

        $this->assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
        $response = json_decode($client->getResponse()->getContent(), true);
        $this->assertStringContainsString(
            'not allowed',
            $response['message'] ?? $response['error'] ?? ''
        );
    }
}
```

### 5.5 Конфигурации для разных тестовых окружений

#### `config/packages/test/octawire_auth.yaml` (основная)

Используется по умолчанию в тестовом окружении. Содержит валидные TLS сертификаты и корректные service auth credentials.

#### `config/packages/test_invalid_secret/octawire_auth.yaml` (неверный секрет)

```yaml
octawire_auth:
    default_project: 'test-project'
    projects:
        test-project:
            # ... остальная конфигурация ...
            service_auth:
                service_name: 'test-service'
                service_secret: 'invalid-secret'  # Неверный секрет
```

#### `config/packages/test_wrong_tls/octawire_auth.yaml` (неверный TLS)

```yaml
octawire_auth:
    default_project: 'test-project'
    projects:
        test-project:
            # ... остальная конфигурация ...
            tls:
                enabled: true
                required: true
                ca_file: '%kernel.project_dir%/config/tls/invalid-ca.crt'  # Неверный CA
                cert_file: '%kernel.project_dir%/config/tls/client.crt'
                key_file: '%kernel.project_dir%/config/tls/client.key'
                server_name: 'localhost'
```

## 6. Полезные команды

```bash
# Запустить только тесты TLS
./bin/phpunit --filter testProtectedEndpointFailsWithInvalidTlsConfiguration tests/Integration/BundleIntegrationTest.php

# Прогнать юнит-тесты с Xdebug coverage
XDEBUG_MODE=coverage vendor/bin/phpunit --testsuite unit --coverage-text

# Запустить конкретный интеграционный тест
cd services/auth-service/clients/php/otus_project2
./bin/phpunit --filter testAdminEndpointWithAdminProjectToken tests/Integration/BundleIntegrationTest.php
```

## 7. Структура тестового приложения (otus_project2)

```
otus_project2/
├── config/
│   ├── packages/
│   │   ├── octawire_auth.yaml          # Основная конфигурация
│   │   ├── security.yaml                # Security firewall
│   │   ├── test/                        # Тестовое окружение
│   │   │   └── octawire_auth.yaml
│   │   ├── test_invalid_secret/         # Окружение с неверным секретом
│   │   │   └── octawire_auth.yaml
│   │   └── test_wrong_tls/              # Окружение с неверным TLS
│   │       └── octawire_auth.yaml
│   └── tls/                             # TLS сертификаты (в .gitignore)
│       ├── dev-ca.crt
│       ├── client.crt
│       └── client.key
├── src/
│   └── Controller/
│       └── TestController.php           # Тестовые эндпоинты
└── tests/
    └── Integration/
        └── BundleIntegrationTest.php    # Интеграционные тесты
```

---

## 8. Примеры интеграционных тестов

В директории `examples/integration-tests/` находятся готовые скрипты для тестирования:

### 8.1 Файлы примеров

| Файл | Описание |
|------|----------|
| `test-client-integration.php` | Тест прямого подключения к Auth Service |
| `test-http-integration.php` | HTTP тест аутентификации через Symfony |
| `config/octawire_auth_no_tls.yaml` | Конфигурация без TLS (development) |
| `config/octawire_auth_with_tls.yaml` | Конфигурация с TLS (production-like) |
| `README.md` | Подробное описание тестов |

### 8.2 Быстрый тест без TLS

```bash
# Терминал 1: Auth Service
cd services/auth-service
./auth-service --config config/config.test.local.json

# Терминал 2: Тест клиента
php examples/integration-tests/test-client-integration.php
```

Ожидаемый вывод:
```
=== Auth Service Client Integration Test ===
✓ AuthClient created
✓ Health check passed
✓ Token issued successfully
✓ Token validated successfully
=== All tests passed! ===
```

### 8.3 HTTP тест с Symfony

```bash
# Терминал 1: Auth Service (уже запущен)

# Терминал 2: Symfony
cd your-symfony-project
php -S localhost:8000 -t public

# Терминал 3: HTTP тест
php examples/integration-tests/test-http-integration.php http://localhost:8000
```

Ожидаемый вывод:
```
=== HTTP Integration Test for Symfony Bundle ===
✓ AuthClient created
✓ Token issued
[Test 2.1] Public endpoint (no auth):
  ✓ Public endpoint works
[Test 2.2] Protected endpoint (no auth - should fail):
  ✓ Correctly rejected (401 Unauthorized)
[Test 2.3] Protected endpoint (with valid token):
  ✓ Protected endpoint works with valid token!
  ✓ User ID: http-test-user-xxx
  ✓ Roles: ["ROLE_ADMIN"]
  ✓ Using camelCase 'userId' field (v0.9.4+)
✅ All HTTP integration tests passed!
```

### 8.4 Переменные окружения

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `AUTH_SERVICE_HOST` | `localhost` | Хост Auth Service |
| `AUTH_SERVICE_PORT` | `50052` | TCP порт Auth Service |
| `AUTH_SERVICE_TLS` | `false` | Включить TLS |
| `AUTH_SERVICE_PROJECT_ID` | `test-project-id` | ID проекта |
| `SYMFONY_URL` | `http://localhost:8000` | URL Symfony приложения |

### 8.5 Копирование примеров в проект

```bash
# Скопировать примеры в ваш проект
cp -r vendor/kabiroman/octawire-auth-service-php-client-bundle/examples/integration-tests ./tests/

# Или создать симлинк
ln -s ../vendor/kabiroman/octawire-auth-service-php-client-bundle/examples/integration-tests ./tests/integration-examples
```

---

## 9. Версии и совместимость

| Версия Bundle | PHP Client | Auth Service | Protocol | JSON Fields |
|--------------|------------|--------------|----------|-------------|
| 0.9.4+ | 0.9.4+ | v0.8.0+ | v1.0 | camelCase |
| 0.9.3 | 0.9.3 | v0.7.x | v0.9 | snake_case |

**Важно**: При обновлении с 0.9.3 на 0.9.4 необходимо учитывать:
- Изменение `healthy` (bool) на `status` (string) в `HealthCheckResponse`
- Добавление обязательного `projectId` в `ValidateTokenRequest`
- Использование camelCase для полей в JSON (`userId`, `projectId`, `tokenType`, etc.)

---

Поддерживайте этот документ актуальным при добавлении новых тестовых сценариев или изменении инфраструктуры. Questions → `TESTING_PLAN.md` (описание стратегий) и `docs/KNOWN_ISSUES.md` (известные проблемы сервиса).


