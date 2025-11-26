# Руководство по установке и настройке Octawire Auth Service Symfony Bundle

Этот документ содержит пошаговые инструкции и примеры конфигурации для различных сценариев использования бандла.

## Содержание

1. [Быстрый старт](#быстрый-старт)
2. [Сценарии использования](#сценарии-использования)
   - [Development окружение (без TLS)](#1-development-окружение-без-tls)
   - [Production с TLS](#2-production-с-tls)
   - [Production с mTLS](#3-production-с-mtls)
   - [С межсервисной аутентификацией](#4-с-межсервисной-аутентификацией)
   - [Multi-project конфигурация](#5-multi-project-конфигурация)
   - [Локальная валидация токенов](#6-локальная-валидация-токенов)
   - [Гибридная валидация](#7-гибридная-валидация)
   - [С Redis кэшем](#8-с-redis-кэшем)
   - [High-load окружение](#9-high-load-окружение)

## Быстрый старт

### 1. Установка

```bash
composer require kabiroman/octawire-auth-service-php-client-bundle
```

### 2. Регистрация Bundle

В `config/bundles.php`:

```php
return [
    // ...
    Kabiroman\Octawire\AuthService\Bundle\OctawireAuthBundle::class => ['all' => true],
];
```

### 3. Минимальная конфигурация

Создайте `config/packages/octawire_auth.yaml`:

```yaml
octawire_auth:
    default_project: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'  # UUID из Auth Service
    projects:
        018fd6d2-8bda-7c61-b01d-12d6eddb02af:
            transport: 'tcp'
            tcp:
                host: 'localhost'
                port: 50052
                persistent: true
            project_id: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
```

### 4. Настройка Security

В `config/packages/security.yaml`:

```yaml
security:
    providers:
        octawire_user_provider:
            id: octawire_auth.user_provider

    firewalls:
        api:
            pattern: ^/api/
            stateless: true
            custom_authenticators:
                - octawire_auth.authenticator
            provider: octawire_user_provider

    access_control:
        - { path: ^/api/, roles: ROLE_USER }
```

Готово! Bundle готов к использованию.

## Сценарии использования

### 1. Development окружение (без TLS)

**Когда использовать:** Локальная разработка, тестирование.

**Особенности:**
- Без TLS шифрования
- Простая настройка
- Быстрый старт

**Конфигурация:**

```yaml
# config/packages/dev/octawire_auth.yaml
octawire_auth:
    default_project: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
    validation_mode: 'remote'
    check_blacklist: true
    projects:
        018fd6d2-8bda-7c61-b01d-12d6eddb02af:
            transport: 'tcp'
            tcp:
                host: 'localhost'
                port: 50052
                persistent: true
                tls:
                    enabled: false  # TLS отключен для development
            project_id: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
            timeout:
                connect: 5.0
                request: 10.0
```

**Security конфигурация:**

```yaml
# config/packages/security.yaml
security:
    providers:
        octawire_user_provider:
            id: octawire_auth.user_provider

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        api:
            pattern: ^/api/
            stateless: true
            custom_authenticators:
                - octawire_auth.authenticator
            provider: octawire_user_provider

    access_control:
        - { path: ^/api/public, roles: PUBLIC_ACCESS }
        - { path: ^/api/, roles: ROLE_USER }
```

### 2. Production с TLS

**Когда использовать:** Production окружение с шифрованием трафика.

**Особенности:**
- TLS шифрование соединения
- Проверка сертификата сервера
- Без mTLS (односторонняя аутентификация)

**Конфигурация:**

```yaml
# config/packages/prod/octawire_auth.yaml
octawire_auth:
    default_project: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
    validation_mode: 'remote'
    check_blacklist: true
    projects:
        018fd6d2-8bda-7c61-b01d-12d6eddb02af:
            transport: 'tcp'
            tcp:
                host: 'auth.example.com'
                port: 50052
                persistent: true
                tls:
                    enabled: true
                    required: true
                    ca_file: '%kernel.project_dir%/config/tls/ca.crt'
                    server_name: 'auth.example.com'  # SNI для проверки сертификата
            project_id: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
            retry:
                max_attempts: 3
                initial_backoff: 0.1
                max_backoff: 5.0
            timeout:
                connect: 10.0
                request: 30.0
```

**Подготовка сертификатов:**

```bash
# CA сертификат должен быть получен от администратора Auth Service
# Разместите его в config/tls/ca.crt
```

### 3. Production с mTLS

**Когда использовать:** Высокий уровень безопасности, взаимная аутентификация клиента и сервера.

**Особенности:**
- Двусторонняя аутентификация (mTLS)
- Клиентский сертификат обязателен
- Максимальная безопасность

**Конфигурация:**

```yaml
# config/packages/prod/octawire_auth.yaml
octawire_auth:
    default_project: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
    validation_mode: 'remote'
    check_blacklist: true
    projects:
        018fd6d2-8bda-7c61-b01d-12d6eddb02af:
            transport: 'tcp'
            tcp:
                host: 'auth.example.com'
                port: 50052
                persistent: true
                tls:
                    enabled: true
                    required: true
                    ca_file: '%kernel.project_dir%/config/tls/ca.crt'
                    cert_file: '%kernel.project_dir%/config/tls/client.crt'  # Клиентский сертификат
                    key_file: '%kernel.project_dir%/config/tls/client.key'   # Приватный ключ клиента
                    server_name: 'auth.example.com'
            project_id: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
            retry:
                max_attempts: 3
            timeout:
                connect: 10.0
                request: 30.0
```

**Подготовка сертификатов:**

```bash
# 1. CA сертификат (от Auth Service)
# config/tls/ca.crt

# 2. Клиентский сертификат и ключ (выдаются администратором)
# config/tls/client.crt
# config/tls/client.key

# Убедитесь, что файлы имеют правильные права доступа:
chmod 600 config/tls/client.key
```

**Важно:** Приватный ключ должен быть защищен от чтения другими пользователями.

### 4. С межсервисной аутентификацией

**Когда использовать:** Сервисы, которые должны аутентифицироваться перед Auth Service для операций валидации.

**Особенности:**
- Service token автоматически запрашивается и кэшируется
- Переиспользование токена до истечения срока
- Автоматическое обновление при приближении к истечению

**Конфигурация:**

```yaml
# config/packages/prod/octawire_auth.yaml
octawire_auth:
    default_project: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
    validation_mode: 'remote'
    check_blacklist: true
    projects:
        018fd6d2-8bda-7c61-b01d-12d6eddb02af:
            transport: 'tcp'
            tcp:
                host: 'auth.example.com'
                port: 50052
                persistent: true
                tls:
                    enabled: true
                    required: true
                    ca_file: '%kernel.project_dir%/config/tls/ca.crt'
                    server_name: 'auth.example.com'
            project_id: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
            service_auth:
                service_name: 'api-gateway'  # Должно быть в allowed_services на Auth Service
                service_secret: '%env(AUTH_SERVICE_SECRET)%'  # Секрет из переменных окружения
            retry:
                max_attempts: 3
            timeout:
                connect: 10.0
                request: 30.0
```

**Переменные окружения (.env):**

```bash
AUTH_SERVICE_SECRET=your-service-secret-here
```

**Как это работает:**

1. При первом запросе `validateToken` бандл автоматически вызывает `issueServiceToken` с `service_name` и `service_secret`
2. Полученный service token кэшируется в памяти
3. Service token используется для всех последующих запросов `validateToken`
4. За 60 секунд до истечения токен автоматически обновляется

### 5. Multi-project конфигурация

**Когда использовать:** Сервис должен принимать токены из разных проектов (например, API v1 и v2, внутренние и внешние токены).

**Особенности:**
- Несколько `project_id` в whitelist
- Разные настройки для каждого проекта
- Автоматическое определение `project_id` из токена

**Конфигурация:**

```yaml
# config/packages/prod/octawire_auth.yaml
octawire_auth:
    # Проект по умолчанию (используется, если project_id не найден в токене)
    default_project: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
    validation_mode: 'remote'
    check_blacklist: true
    projects:
        # API v1 - RS256 токены
        018fd6d2-8bda-7c61-b01d-12d6eddb02af:
            transport: 'tcp'
            tcp:
                host: 'auth.example.com'
                port: 50052
                persistent: true
                tls:
                    enabled: true
                    required: true
                    ca_file: '%kernel.project_dir%/config/tls/ca.crt'
                    server_name: 'auth.example.com'
            project_id: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
            service_auth:
                service_name: 'api-gateway'
                service_secret: '%env(AUTH_SERVICE_SECRET)%'
            key_cache:
                driver: 'memory'
                ttl: 3600
                max_size: 100
        
        # API v2 - ES256 токены
        018fd6d2-91da-7c77-b40d-abcdef012345:
            transport: 'tcp'
            tcp:
                host: 'auth.example.com'
                port: 50052
                persistent: true
                tls:
                    enabled: true
                    required: true
                    ca_file: '%kernel.project_dir%/config/tls/ca.crt'
                    server_name: 'auth.example.com'
            project_id: '018fd6d2-91da-7c77-b40d-abcdef012345'
            service_auth:
                service_name: 'api-gateway'
                service_secret: '%env(AUTH_SERVICE_SECRET)%'
            key_cache:
                driver: 'memory'
                ttl: 3600
        
        # Внутренние сервисы - HS256 токены
        018fd6d2-9acd-7d71-bf1d-fedcba987654:
            transport: 'tcp'
            tcp:
                host: 'auth-internal.example.com'
                port: 50052
                persistent: true
                tls:
                    enabled: true
                    required: true
                    ca_file: '%kernel.project_dir%/config/tls/internal-ca.crt'
                    cert_file: '%kernel.project_dir%/config/tls/internal-client.crt'
                    key_file: '%kernel.project_dir%/config/tls/internal-client.key'
                    server_name: 'auth-internal.example.com'
            project_id: '018fd6d2-9acd-7d71-bf1d-fedcba987654'
            service_auth:
                service_name: 'internal-api'
                service_secret: '%env(INTERNAL_AUTH_SECRET)%'
            key_cache:
                driver: 'redis'
                ttl: 7200
```

**Поведение:**

- Токены с `project_id`, не указанным в конфигурации, автоматически отклоняются
- Если токен содержит `project_id` в claims, используется соответствующий проект
- Если токен не содержит `project_id`, используется `default_project`
- Если `default_project` не настроен и токен не содержит `project_id`, токен отклоняется

### 6. Локальная валидация токенов

**Когда использовать:** Высоконагруженные сервисы, требующие минимальной задержки, или когда Auth Service может быть недоступен.

**Особенности:**
- Валидация подписи локально (без сетевых запросов)
- Проверка истечения срока действия
- Не проверяет blacklist (требует отдельной логики или пропуска)
- Кэширование публичных ключей

**Конфигурация:**

```yaml
# config/packages/prod/octawire_auth.yaml
octawire_auth:
    default_project: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
    validation_mode: 'local'  # Локальная валидация
    check_blacklist: false    # Не используется в local режиме
    projects:
        018fd6d2-8bda-7c61-b01d-12d6eddb02af:
            transport: 'tcp'
            tcp:
                host: 'auth.example.com'
                port: 50052
                persistent: true
                tls:
                    enabled: true
                    required: true
                    ca_file: '%kernel.project_dir%/config/tls/ca.crt'
                    server_name: 'auth.example.com'
            project_id: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
            # Публичные ключи запрашиваются автоматически и кэшируются
            key_cache:
                driver: 'memory'
                ttl: 3600  # Кэш ключей на 1 час
                max_size: 100
            timeout:
                connect: 10.0
                request: 30.0
```

**Преимущества:**
- ✅ Нет сетевых запросов при валидации
- ✅ Работает даже при недоступности Auth Service
- ✅ Минимальная задержка

**Ограничения:**
- ⚠️ Не проверяет blacklist (отозванные токены могут быть приняты)
- ⚠️ Требует синхронизации публичных ключей

### 7. Гибридная валидация

**Когда использовать:** Компромисс между производительностью и безопасностью. Локальная проверка подписи + удаленная проверка blacklist.

**Особенности:**
- Локальная проверка подписи (быстро)
- Удаленная проверка blacklist (безопасно)
- Кэширование публичных ключей

**Конфигурация:**

```yaml
# config/packages/prod/octawire_auth.yaml
octawire_auth:
    default_project: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
    validation_mode: 'hybrid'  # Гибридная валидация
    check_blacklist: true      # Проверка blacklist через Auth Service
    projects:
        018fd6d2-8bda-7c61-b01d-12d6eddb02af:
            transport: 'tcp'
            tcp:
                host: 'auth.example.com'
                port: 50052
                persistent: true
                tls:
                    enabled: true
                    required: true
                    ca_file: '%kernel.project_dir%/config/tls/ca.crt'
                    server_name: 'auth.example.com'
            project_id: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
            service_auth:
                service_name: 'api-gateway'
                service_secret: '%env(AUTH_SERVICE_SECRET)%'
            key_cache:
                driver: 'memory'
                ttl: 3600
                max_size: 100
            timeout:
                connect: 10.0
                request: 30.0
```

**Как это работает:**

1. Токен проверяется локально (подпись, срок действия)
2. Если локальная проверка успешна, отправляется запрос на проверку blacklist
3. Если токен в blacklist, валидация отклоняется
4. Публичные ключи кэшируются для быстрого доступа

**Рекомендации:**
- Идеально для Gateway сервисов
- Баланс между производительностью и безопасностью

### 8. С Redis кэшем

**Когда использовать:** Несколько экземпляров приложения, распределенный кэш публичных ключей.

**Особенности:**
- Общий кэш между экземплярами приложения
- Синхронизация публичных ключей
- Уменьшение нагрузки на Auth Service

**Конфигурация:**

```yaml
# config/packages/prod/octawire_auth.yaml
octawire_auth:
    default_project: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
    validation_mode: 'hybrid'
    check_blacklist: true
    projects:
        018fd6d2-8bda-7c61-b01d-12d6eddb02af:
            transport: 'tcp'
            tcp:
                host: 'auth.example.com'
                port: 50052
                persistent: true
                tls:
                    enabled: true
                    required: true
                    ca_file: '%kernel.project_dir%/config/tls/ca.crt'
                    server_name: 'auth.example.com'
            project_id: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
            service_auth:
                service_name: 'api-gateway'
                service_secret: '%env(AUTH_SERVICE_SECRET)%'
            key_cache:
                driver: 'redis'
                ttl: 7200  # 2 часа
                max_size: 200
            redis:
                host: '%env(REDIS_HOST)%'
                port: '%env(int:REDIS_PORT)%'
                db: 0
                password: '%env(REDIS_PASSWORD)%'
            timeout:
                connect: 10.0
                request: 30.0
```

**Переменные окружения:**

```bash
REDIS_HOST=redis.example.com
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password
```

**Требования:**

- Установленный и настроенный Redis
- Доступ к Redis из всех экземпляров приложения

### 9. High-load окружение

**Когда использовать:** Высоконагруженные сервисы с требованиями к производительности.

**Особенности:**
- Локальная валидация для минимальной задержки
- Persistent соединения
- Оптимизированные таймауты
- Кэширование ключей

**Конфигурация:**

```yaml
# config/packages/prod/octawire_auth.yaml
octawire_auth:
    default_project: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
    validation_mode: 'local'  # Локальная валидация для максимальной производительности
    check_blacklist: false
    projects:
        018fd6d2-8bda-7c61-b01d-12d6eddb02af:
            transport: 'tcp'
            tcp:
                host: 'auth.example.com'
                port: 50052
                persistent: true  # Переиспользование соединений
                tls:
                    enabled: true
                    required: true
                    ca_file: '%kernel.project_dir%/config/tls/ca.crt'
                    server_name: 'auth.example.com'
            project_id: '018fd6d2-8bda-7c61-b01d-12d6eddb02af'
            # Redis для распределенного кэша
            key_cache:
                driver: 'redis'
                ttl: 7200  # Длительный TTL для уменьшения запросов
                max_size: 500
            redis:
                host: '%env(REDIS_HOST)%'
                port: '%env(int:REDIS_PORT)%'
                db: 0
                password: '%env(REDIS_PASSWORD)%'
            # Оптимизированные таймауты
            timeout:
                connect: 5.0   # Быстрое подключение
                request: 15.0  # Быстрый ответ
            # Агрессивные retry настройки
            retry:
                max_attempts: 2  # Меньше попыток для быстрого отказа
                initial_backoff: 0.05
                max_backoff: 1.0
```

**Дополнительные рекомендации:**

1. Используйте Redis для кэша ключей между экземплярами
2. Настройте мониторинг производительности
3. Рассмотрите использование гибридного режима, если нужна проверка blacklist

## Настройка Security

### Базовая конфигурация

```yaml
# config/packages/security.yaml
security:
    providers:
        octawire_user_provider:
            id: octawire_auth.user_provider

    firewalls:
        api:
            pattern: ^/api/
            stateless: true
            custom_authenticators:
                - octawire_auth.authenticator
            provider: octawire_user_provider

    access_control:
        - { path: ^/api/public, roles: PUBLIC_ACCESS }
        - { path: ^/api/, roles: ROLE_USER }
        - { path: ^/api/admin, roles: ROLE_ADMIN }

    role_hierarchy:
        ROLE_ADMIN: ROLE_USER
```

### Расширенная конфигурация с несколькими firewall

```yaml
# config/packages/security.yaml
security:
    providers:
        octawire_user_provider:
            id: octawire_auth.user_provider

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        
        # Публичный API
        api_public:
            pattern: ^/api/public
            stateless: true
            custom_authenticators:
                - octawire_auth.authenticator
            provider: octawire_user_provider
        
        # Защищенный API
        api:
            pattern: ^/api/
            stateless: true
            custom_authenticators:
                - octawire_auth.authenticator
            provider: octawire_user_provider
        
        # Админский API
        api_admin:
            pattern: ^/api/admin
            stateless: true
            custom_authenticators:
                - octawire_auth.authenticator
            provider: octawire_user_provider

    access_control:
        - { path: ^/api/public, roles: PUBLIC_ACCESS }
        - { path: ^/api/admin, roles: ROLE_ADMIN }
        - { path: ^/api/, roles: ROLE_USER }

    role_hierarchy:
        ROLE_ADMIN: ROLE_USER
        ROLE_SUPER_ADMIN: [ROLE_ADMIN, ROLE_USER]
```

## Использование в контроллерах

### Базовый пример

```php
<?php

namespace App\Controller;

use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireUser;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class ApiController extends AbstractController
{
    #[Route('/api/user', name: 'api_user', methods: ['GET'])]
    #[IsGranted('ROLE_USER')]
    public function getUserInfo(): JsonResponse
    {
        $user = $this->getUser();
        
        if (!$user instanceof OctowireUser) {
            return $this->json(['error' => 'User not found'], 401);
        }

        return $this->json([
            'user_id' => $user->getUserId(),
            'identifier' => $user->getUserIdentifier(),
            'roles' => $user->getRoles(),
            'claims' => $user->getClaims(),
        ]);
    }
}
```

### Работа с кастомными claims

```php
#[Route('/api/profile', name: 'api_profile', methods: ['GET'])]
#[IsGranted('ROLE_USER')]
public function getProfile(): JsonResponse
{
    $user = $this->getUser();
    
    if (!$user instanceof OctowireUser) {
        return $this->json(['error' => 'User not found'], 401);
    }

    // Получение кастомных claims
    $email = $user->getClaim('email');
    $department = $user->getClaim('department', 'unknown');
    $permissions = $user->getClaim('permissions', []);

    return $this->json([
        'user_id' => $user->getUserId(),
        'email' => $email,
        'department' => $department,
        'permissions' => $permissions,
    ]);
}
```

### Проверка ролей

```php
#[Route('/api/admin/users', name: 'api_admin_users', methods: ['GET'])]
#[IsGranted('ROLE_ADMIN')]
public function listUsers(): JsonResponse
{
    $user = $this->getUser();
    
    // Дополнительная проверка роли из claims
    if ($user instanceof OctowireUser) {
        $roleFromToken = $user->getClaim('role');
        if ($roleFromToken !== 'ROLE_ADMIN') {
            return $this->json(['error' => 'Insufficient permissions'], 403);
        }
    }

    // Логика получения списка пользователей
    return $this->json(['users' => []]);
}
```

## Переменные окружения

Рекомендуется использовать переменные окружения для чувствительных данных:

```bash
# .env
AUTH_SERVICE_SECRET=your-service-secret-here
INTERNAL_AUTH_SECRET=internal-service-secret
REDIS_HOST=redis.example.com
REDIS_PORT=6379
REDIS_PASSWORD=redis-password
```

Использование в конфигурации:

```yaml
service_auth:
    service_name: 'api-gateway'
    service_secret: '%env(AUTH_SERVICE_SECRET)%'

redis:
    host: '%env(REDIS_HOST)%'
    port: '%env(int:REDIS_PORT)%'
    password: '%env(REDIS_PASSWORD)%'
```

## Проверка конфигурации

После настройки проверьте, что все работает:

```bash
# Проверка конфигурации Symfony
php bin/console debug:config octawire_auth

# Проверка зарегистрированных сервисов
php bin/console debug:container octawire_auth

# Проверка firewall
php bin/console debug:firewall
```

## Устранение проблем

### Проблема: "Token project ID is not allowed"

**Причина:** Токен содержит `project_id`, который не указан в конфигурации.

**Решение:** Добавьте `project_id` в секцию `projects` или настройте `default_project`.

### Проблема: "Connection failed"

**Причина:** Auth Service недоступен или неправильная конфигурация TLS.

**Решение:**
1. Проверьте доступность Auth Service
2. Проверьте правильность пути к TLS сертификатам
3. Убедитесь, что `server_name` соответствует сертификату

### Проблема: "Service authentication failed"

**Причина:** Неверный `service_secret` или `service_name` не в whitelist.

**Решение:**
1. Проверьте правильность `service_secret`
2. Убедитесь, что `service_name` добавлен в `allowed_services` на Auth Service

## Дополнительные ресурсы

- [README.md](README.md) - Общая документация бандла
- [TESTING.md](TESTING.md) - Руководство по тестированию
- [examples/](examples/) - Примеры использования

