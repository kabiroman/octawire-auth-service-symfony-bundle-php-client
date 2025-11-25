# Octawire Auth Service Symfony Bundle

Symfony Bundle для интеграции PHP клиента Octawire Auth Service с Symfony Security Component.

## Требования

- PHP 8.1+
- Symfony 7.0+
- `kabiroman/octawire-auth-service-php-client` ^0.9.1
- `ext-sockets` (для TCP соединений)
- `ext-json` (для JSON обработки)

> **Важно:** Bundle использует TCP/JATP транспорт, **не требует gRPC extension**.

## Установка

```bash
composer require kabiroman/octawire-auth-service-php-client-bundle
```

## Конфигурация

### 1. Зарегистрируйте Bundle

В `config/bundles.php`:

```php
return [
    // ...
    Kabiroman\Octawire\AuthService\Bundle\OctawireAuthBundle::class => ['all' => true],
];
```

### 2. Настройте Bundle

Создайте файл `config/packages/octawire_auth.yaml`:

```yaml
octawire_auth:
    default_project: 'project-1'  # Проект по умолчанию
    projects:
        project-1:
            transport: 'tcp'
            tcp:
                host: 'localhost'
                port: 50052  # TCP/JATP порт (по умолчанию 50052)
                persistent: true  # Переиспользование соединений
                tls:
                    enabled: false  # true для production
                    # ca_file: '%kernel.project_dir%/config/tls/ca.crt'
                    # cert_file: '%kernel.project_dir%/config/tls/client.crt'  # для mTLS
                    # key_file: '%kernel.project_dir%/config/tls/client.key'  # для mTLS
            project_id: 'project-1'
            api_key: '%env(AUTH_API_KEY)%'
            retry:
                max_attempts: 3
            key_cache:
                driver: 'memory'
                ttl: 3600
        project-2:
            transport: 'tcp'
            tcp:
                host: 'auth.example.com'
                port: 50052
                persistent: true
                tls:
                    enabled: true
                    ca_file: '%kernel.project_dir%/config/tls/ca.crt'
                    server_name: 'auth.example.com'
            project_id: 'project-2'
```

### 3. Настройте Security

В `config/packages/security.yaml`:

```yaml
security:
    firewalls:
        api:
            pattern: ^/api/
            stateless: true
            custom_authenticators:
                - octawire_auth.authenticator
            access_control:
                - { path: ^/api/, roles: ROLE_USER }
```

## Использование

### Автоматическая валидация токенов

Bundle автоматически валидирует JWT токены из заголовка `Authorization: Bearer <token>` для всех запросов, соответствующих паттерну firewall.

Валидация происходит через TCP/JATP соединение с Auth Service, используя метод `ValidateToken`.

### Доступ к пользователю в контроллерах

```php
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireUser;
use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireToken;

class ApiController extends AbstractController
{
    #[IsGranted('ROLE_USER')]
    public function index(): JsonResponse
    {
        $user = $this->getUser();
        
        if ($user instanceof OctowireUser) {
            $userId = $user->getUserId();
            $claims = $user->getClaims();
            $role = $user->getClaim('role');
        }

        return $this->json(['user' => $userId]);
    }
}
```

### Доступ к токену

```php
use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireToken;

// В контроллере
$token = $this->getToken();
if ($token instanceof OctowireToken) {
    $jwtToken = $token->getJwtToken();
    $projectId = $token->getProjectId();
    $claims = $token->getClaims();
}
```

### Работа с несколькими проектами

Bundle поддерживает работу с несколькими проектами. Project ID может быть:
1. Извлечен из токена (из claims)
2. Указан в конфигурации как `default_project`
3. Определен динамически на основе токена

### Использование AuthClient напрямую

```php
use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;

class MyService
{
    public function __construct(
        private AuthClientFactory $clientFactory
    ) {}

    public function issueToken(string $userId): array
    {
        $client = $this->clientFactory->getClient('project-1');
        return $client->issueToken([
            'user_id' => $userId,
            'claims' => ['role' => 'admin'],
        ]);
    }
}
```

## Конфигурация проектов

Каждый проект может иметь следующие настройки:

- `transport` (опционально, по умолчанию 'tcp') - транспорт ('tcp' для TCP/JATP)
- `tcp` (обязательно для TCP транспорта) - конфигурация TCP соединения
  - `host` (обязательно) - хост TCP сервера
  - `port` (обязательно) - порт TCP сервера (по умолчанию 50052)
  - `persistent` (опционально, по умолчанию true) - использовать persistent соединения
- `project_id` (обязательно) - ID проекта
- `api_key` (опционально) - API ключ для аутентификации
- `tcp.tls` - настройки TLS/mTLS для TCP соединения
  - `enabled` - включить TLS (обязательно для production)
  - `required` - требовать TLS (не подключится если TLS недоступен)
  - `cert_file` - путь к сертификату клиента (для mTLS)
  - `key_file` - путь к приватному ключу (для mTLS)
  - `ca_file` - путь к CA сертификату
  - `server_name` - имя сервера для проверки TLS (SNI)
- `retry` - настройки повторных попыток
  - `max_attempts` - максимальное количество попыток
  - `initial_backoff` - начальная задержка (секунды)
  - `max_backoff` - максимальная задержка (секунды)
- `key_cache` - настройки кэширования ключей
  - `driver` - драйвер ('memory' или 'redis')
  - `ttl` - время жизни кэша (секунды)
  - `max_size` - максимальное количество проектов в кэше
- `redis` - настройки Redis (если используется для кэша)
  - `host` - хост Redis
  - `port` - порт Redis
  - `db` - номер базы данных
  - `password` - пароль (опционально)
- `timeout` - настройки таймаутов
  - `connect` - таймаут подключения (секунды)
  - `request` - таймаут запроса (секунды)

## Обработка ошибок

Bundle автоматически обрабатывает ошибки валидации токенов:

- `InvalidTokenException` → `BadCredentialsException`
- `TokenExpiredException` → `BadCredentialsException`
- `TokenRevokedException` → `BadCredentialsException`

Все ошибки возвращаются в формате JSON с кодом 401 (Unauthorized).

## Примеры

Полные примеры использования находятся в директории `examples/`.

## Лицензия

MIT License




