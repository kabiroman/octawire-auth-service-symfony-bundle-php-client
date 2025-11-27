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

> 📖 **Подробное руководство:** Для детальных инструкций по установке и настройке для различных сценариев использования см. [INSTALLATION.md](INSTALLATION.md)

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
    # Значения default_project и project_id — это UUID проектов, заданные в конфигурации Auth Service
    default_project: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
    projects:
        018fd6d2-8bda-7c61-b01d-12d6eddb02af:
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
            project_id: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
            api_key: '%env(AUTH_API_KEY)%'
            retry:
                max_attempts: 3
            key_cache:
                driver: 'memory'
                ttl: 3600
        018fd6d2-91da-7c77-b40d-abcdef012345:
            transport: 'tcp'
            tcp:
                host: 'auth.example.com'
                port: 50052
                persistent: true
                tls:
                    enabled: true
                    ca_file: '%kernel.project_dir%/config/tls/ca.crt'
                    server_name: 'auth.example.com'
            project_id: '018fd6d2-91da-7c77-b40d-abcdef012345'
            service_auth:
                service_name: 'api-gateway'
                service_secret: '%env(AUTH_SERVICE_SECRET)%'
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

### Концепция project_id

**Важно:** `project_id` используется для разделения разных типов токенов и алгоритмов подписи.

#### Архитектурная концепция

- **Разные типы токенов:** Разные `project_id` могут использовать разные алгоритмы подписи (RS256, ES256, HS256 и т.д.)
- **Whitelist подход:** Каждый сервис настраивается на работу только с определенными `project_id` (whitelist)
- **Безопасность:** Токены с `project_id`, не указанным в конфигурации, автоматически отклоняются до валидации
- **Контроль доступа:** Это позволяет контролировать, какие типы токенов сервис принимает

#### Пример использования

```yaml
octawire_auth:
    default_project: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'  # Проект по умолчанию (UUID)
    projects:
        018fd6d2-8bda-7c61-b01d-12d6eddb02af:  # Токены для API v1 (RS256)
            transport: 'tcp'
            tcp:
                host: 'auth.example.com'
                port: 50052
            project_id: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
            key_cache:
                driver: 'memory'
                ttl: 3600
        
        018fd6d2-91da-7c77-b40d-abcdef012345:  # Токены для API v2 (ES256)
            transport: 'tcp'
            tcp:
                host: 'auth.example.com'
                port: 50052
            project_id: '018fd6d2-91da-7c77-b40d-abcdef012345'
            key_cache:
                driver: 'memory'
                ttl: 3600
        
        018fd6d2-9acd-7d71-bf1d-fedcba987654:  # Внутренние токены (HS256)
            transport: 'tcp'
            tcp:
                host: 'auth-internal.example.com'
                port: 50052
            project_id: '018fd6d2-9acd-7d71-bf1d-fedcba987654'
            key_cache:
                driver: 'redis'
                ttl: 3600
```

**Поведение:**
- Сервис будет принимать токены только с перечисленными UUID
- Токены с другими `project_id` будут отклонены с ошибкой: `Token project ID "..."`
- Если токен не содержит `project_id` в claims, используется `default_project`
- Если токен не содержит `project_id` и `default_project` не настроен, токен будет отклонен

#### Логика выбора project_id

1. **Из токена:** Если токен содержит `project_id` в claims (или `aud`), используется он
2. **Whitelist проверка:** Проверяется, что `project_id` из токена присутствует в конфигурации
3. **Default fallback:** Если `project_id` не найден в токене, используется `default_project`
4. **Ошибка:** Если `project_id` не найден в токене и `default_project` не настроен, токен отклоняется

### Режимы валидации токенов

Bundle поддерживает три режима валидации токенов:

#### Режим 1: Remote Validation (по умолчанию)

Полная валидация через Auth Service:

- ✅ Проверка blacklist
- ✅ Полная валидация всех аспектов токена
- ✅ Централизованное управление
- ⚠️ Зависимость от доступности Auth Service
- ⚠️ Сетевая задержка на каждый запрос

**Конфигурация:**
```yaml
octawire_auth:
    validation_mode: 'remote'  # По умолчанию
    check_blacklist: true
    # ...
```

#### Режим 2: Local Validation

Локальная проверка подписи с использованием публичных ключей:

- ✅ Независимость от доступности Auth Service
- ✅ Низкая задержка (нет сетевых запросов)
- ✅ Меньше нагрузки на Auth Service
- ⚠️ Не проверяет blacklist (требует отдельной проверки или пропуска)
- ⚠️ Требует синхронизации публичных ключей

**Конфигурация:**
```yaml
octawire_auth:
    validation_mode: 'local'
    check_blacklist: false  # Не используется в local режиме
    # ...
```

#### Режим 3: Hybrid Validation

Локальная проверка подписи + удаленная проверка blacklist:

- ✅ Компромисс между производительностью и безопасностью
- ✅ Локальная проверка подписи + удаленная проверка blacklist
- ⚠️ Требует доступности Auth Service для проверки blacklist

**Конфигурация:**
```yaml
octawire_auth:
    validation_mode: 'hybrid'
    check_blacklist: true  # Проверка blacklist через Auth Service
    # ...
```

**Рекомендации:**
- **Gateway Service**: Hybrid режим для максимальной производительности + проверка blacklist
- **Другие сервисы**: Remote режим для простоты
- **High-load окружения**: Local режим для независимости от Auth Service

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
- `project_id` (обязательно) - UUID проекта, выданный Auth Service
- `service_auth` (опционально) - параметры межсервисной аутентификации:
  - `service_name` — имя сервиса (должно совпадать с whitelist на Auth Service)
  - `service_secret` — секрет сервиса, используемый для выдачи service-token
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

> Bundle автоматически запрашивает service-token через `issueServiceToken`, кеширует его до истечения `exp` и переиспользует для удалённых проверок (remote/hybrid/blacklist). Некорректный секрет, неразрешённый `service_name` или истекший токен приводят к отказу аутентификации. При включённом `tcp.tls.enabled` рекомендуется указывать `server_name` и CA файлы; для mTLS добавьте `cert_file`/`key_file`.

## Service Authentication

Service Authentication используется для межсервисной аутентификации при вызове методов Auth Service (например, `ValidateToken`). Это дополнительный слой защиты поверх TLS/mTLS.

### Настройка

Service authentication настраивается **per-project** - каждый проект может иметь свой собственный `service_name` и `service_secret`:

```yaml
octawire_auth:
    projects:
        project-1:
            project_id: 'project-1'
            service_auth:
                service_name: 'api-gateway'
                service_secret: '%env(API_GATEWAY_SERVICE_SECRET)%'
        project-2:
            project_id: 'project-2'
            service_auth:
                service_name: 'internal-api'
                service_secret: '%env(INTERNAL_API_SERVICE_SECRET)%'
```

### Как это работает

1. Bundle автоматически определяет `project_id` из токена или использует `default_project`
2. Для каждого `project_id` используется соответствующий `service_name` и `service_secret` из конфигурации
3. При необходимости валидации токена Bundle автоматически выдает service token используя `IssueServiceToken`
4. Service token кэшируется per-project до истечения `exp`
5. Service token используется для аутентификации при вызове методов Auth Service

### Обработка ошибок

При неудачной валидации service credentials сервер возвращает ошибку `AUTH_FAILED`:

- Bundle автоматически обрабатывает `AUTH_FAILED` и выбрасывает `AuthenticationException` с понятным сообщением
- В логах записывается информация о project_id и service_name для отладки
- Ошибка указывает на необходимость проверки конфигурации `service_name` и `service_secret` для конкретного проекта

### Безопасное хранение секретов

**Важно:**
- Не храните `service_secret` в коде или конфигурациях
- Используйте переменные окружения и secrets manager
- Ротируйте секреты и используйте разные значения для окружений
- Отзывайте скомпрометированные секреты немедленно

**Рекомендации:**
```yaml
octawire_auth:
    projects:
        project-1:
            project_id: 'project-1'
            service_auth:
                service_name: 'api-gateway'
                service_secret: '%env(API_GATEWAY_SERVICE_SECRET)%'  # Используйте переменные окружения
```

### Кейсы подключения

Bundle поддерживает 4 кейса подключения согласно конфигурациям сервиса:

1. **PROD + service_auth=false**: TLS обязателен (tcp.tls.enabled=true, tcp.tls.required=true), без service auth
2. **PROD + service_auth=true**: TLS обязателен + service authentication
3. **DEV + service_auth=false**: TLS опционален (tcp.tls.enabled=false), без service auth
4. **DEV + service_auth=true**: TLS опционален + service authentication

**Пример 1: PROD + service_auth=false**
```yaml
octawire_auth:
    projects:
        project-1:
            transport: 'tcp'
            tcp:
                host: 'auth-service.example.com'
                port: 50052
                tls:
                    enabled: true
                    required: true
                    ca_file: '%kernel.project_dir%/config/tls/ca.crt'
                    server_name: 'auth-service.example.com'
            project_id: 'project-1'
            # service_auth не указан
```

**Пример 2: PROD + service_auth=true**
```yaml
octawire_auth:
    projects:
        project-1:
            transport: 'tcp'
            tcp:
                host: 'auth-service.example.com'
                port: 50052
                tls:
                    enabled: true
                    required: true
                    ca_file: '%kernel.project_dir%/config/tls/ca.crt'
                    cert_file: '%kernel.project_dir%/config/tls/client.crt'  # для mTLS
                    key_file: '%kernel.project_dir%/config/tls/client.key'  # для mTLS
                    server_name: 'auth-service.example.com'
            project_id: 'project-1'
            service_auth:
                service_name: 'api-gateway'
                service_secret: '%env(API_GATEWAY_SERVICE_SECRET)%'
```

**Пример 3: DEV + service_auth=false**
```yaml
octawire_auth:
    projects:
        project-1:
            transport: 'tcp'
            tcp:
                host: 'localhost'
                port: 50052
                tls:
                    enabled: false  # TLS опционален в DEV
            project_id: 'project-1'
            # service_auth не указан
```

**Пример 4: DEV + service_auth=true**
```yaml
octawire_auth:
    projects:
        project-1:
            transport: 'tcp'
            tcp:
                host: 'localhost'
                port: 50052
                tls:
                    enabled: false  # TLS опционален в DEV
            project_id: 'project-1'
            service_auth:
                service_name: 'dev-service'
                service_secret: 'dev-service-secret-abc123'  # для service authentication
```

### Соответствие спецификациям

Bundle полностью соответствует:
- **SECURITY.md** - требованиям по service authentication и безопасному хранению секретов
- **JATP_METHODS_1.0.json** - обработке всех кодов ошибок, включая `AUTH_FAILED`

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




