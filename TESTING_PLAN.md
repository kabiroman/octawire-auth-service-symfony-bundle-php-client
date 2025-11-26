# План тестирования Symfony Bundle

## 📋 Обзор

Этот документ описывает стратегию тестирования Symfony Bundle для Octawire Auth Service PHP Client. Bundle интегрирует TCP/JATP клиент с Symfony Security Component для автоматической валидации JWT токенов.

## 🎯 Цели тестирования

- Убедиться, что Bundle правильно регистрируется и настраивается в Symfony
- Проверить интеграцию с Symfony Security Component
- Валидировать работу всех компонентов (Authenticator, TokenValidator, Factory)
- Обеспечить покрытие кода > 80%

## 📁 Структура тестов

### Текущая структура

```
tests/
├── Unit/                              # ✅ Unit тесты с моками
│   ├── Security/
│   │   └── OctowireTokenAuthenticatorTest.php
│   └── Service/
│       └── TokenValidatorTest.php
└── Functional/                        # ⚠️ Базовые функциональные тесты
    └── SecurityIntegrationTest.php
```

### Целевая структура

```
tests/
├── Fixtures/                          # Тестовые конфигурации и TestKernel
│   ├── TestKernel.php                # TestKernel для изоляции тестов
│   └── config/
│       ├── test_bundle.yaml          # Тестовая конфигурация bundle
│       ├── test_security.yaml        # Тестовая Security конфигурация
│       └── test_services.yaml        # Тестовая конфигурация сервисов
├── Unit/                              # Unit тесты (с моками)
│   ├── Security/
│   │   ├── OctowireTokenAuthenticatorTest.php
│   │   ├── OctowireTokenTest.php     # Новый: тесты токена
│   │   └── OctowireUserTest.php      # Новый: тесты пользователя
│   ├── Service/
│   │   └── TokenValidatorTest.php
│   └── Factory/
│       └── AuthClientFactoryTest.php # Новый: тесты фабрики
└── Functional/                        # Functional тесты с Symfony Kernel
    ├── KernelTestCase.php            # Базовый класс для Kernel тестов
    ├── BundleConfigurationTest.php   # Тесты конфигурации Bundle
    ├── SecurityIntegrationTest.php   # Обновить: полная интеграция Security
    └── AuthenticatorIntegrationTest.php # Полный цикл аутентификации
```

## 🧪 Типы тестов

### 1. Unit тесты (с моками)

**Назначение:** Тестирование изолированных компонентов без зависимостей от Symfony Kernel.

**Компоненты для тестирования:**

#### ✅ TokenValidator
- [x] `extractProjectIdFromToken()` - извлечение project_id из токена
- [ ] `validateToken()` - валидация токена через AuthClient
- [ ] Обработка различных типов ошибок (TokenExpiredException, TokenRevokedException, InvalidTokenException)
- [ ] Fallback на default project_id

#### ✅ OctowireTokenAuthenticator
- [x] `supports()` - определение поддерживаемых запросов
- [ ] `authenticate()` - полный цикл аутентификации
- [ ] `createToken()` - создание OctowireToken
- [ ] `onAuthenticationSuccess()` и `onAuthenticationFailure()`
- [ ] `start()` - entry point для аутентификации

#### ⏳ OctowireToken
- [ ] Создание токена с claims
- [ ] Извлечение project_id, user_id, claims
- [ ] Сериализация/десериализация

#### ⏳ OctowireUser
- [x] `fromClaims()` - создание пользователя из claims
- [ ] `getRoles()` - извлечение ролей из claims
- [ ] `getClaims()` и `getClaim()`
- [ ] Обработка различных форматов claims

#### ⏳ AuthClientFactory
- [ ] `getClient()` - получение клиента по project_id
- [ ] Использование default_project
- [ ] Обработка несуществующих проектов
- [ ] `hasProject()` и `getProjectIds()`

### 2. Functional тесты (с Symfony Kernel)

**Назначение:** Тестирование в контексте реального Symfony приложения с загруженным Bundle.

**Требования:**
- `Symfony\Bundle\FrameworkBundle\Test\KernelTestCase`
- Тестовый Kernel (`TestKernel`)
- Тестовые конфигурации Bundle

#### BundleConfigurationTest

**Тесты конфигурации Bundle:**

- [ ] **Регистрация Bundle**
  - Bundle регистрируется в Kernel
  - Extension загружается корректно
  - Services регистрируются в container

- [ ] **Загрузка конфигурации**
  - YAML конфигурация парсится корректно
  - Валидация обязательных полей (`tcp.host`, `tcp.port`, `project_id`)
  - Обработка опциональных полей
  - Валидация типов (port должен быть integer)

- [ ] **Создание сервисов**
  - `octawire_auth.client_factory` создается
  - `octawire_auth.token_validator` создается
  - `octawire_auth.authenticator` создается
  - `octawire_auth.user_provider` создается
  - AuthClient для каждого проекта создается

- [ ] **Валидация конфигурации**
  - XSD схема валидирует корректную конфигурацию
  - Некорректная конфигурация вызывает ошибку
  - Валидация TCP конфигурации (host, port, TLS)

- [ ] **Множественные проекты**
  - Несколько проектов конфигурируются корректно
  - Каждый проект имеет свой AuthClient
  - Default project работает корректно

#### SecurityIntegrationTest

**Тесты интеграции с Symfony Security:**

- [ ] **Регистрация Authenticator**
  - Authenticator регистрируется в Security firewall
  - Firewall использует authenticator для запросов
  - Entry point работает корректно

- [ ] **Полный цикл аутентификации**
  - Request с Bearer токеном → Authenticator обрабатывает
  - Токен валидируется через TokenValidator
  - OctowireUser создается из claims
  - OctowireToken создается и сохраняется
  - Пользователь доступен через `$this->getUser()`

- [ ] **Извлечение токена**
  - Токен извлекается из `Authorization: Bearer <token>`
  - Запросы без токена отклоняются (401)
  - Некорректный формат Authorization header обрабатывается

- [ ] **Валидация токена**
  - Валидный токен проходит валидацию
  - Невалидный токен отклоняется (401)
  - Истекший токен отклоняется (401)
  - Отозванный токен отклоняется (401)

- [ ] **Создание пользователя**
  - OctowireUser создается из claims
  - Роли извлекаются из claims (`role`, `roles`)
  - User ID извлекается (`user_id`, `sub`)

- [ ] **Обработка ошибок**
  - Ошибки валидации возвращают JSON ответ 401
  - Сообщения об ошибках понятны
  - Исключения оборачиваются корректно

#### AuthenticatorIntegrationTest

**Тесты полной интеграции Authenticator:**

- [ ] **HTTP запросы с токенами**
  - GET запрос с валидным токеном → 200 OK
  - POST запрос с валидным токеном → 200 OK
  - Запрос без токена → 401 Unauthorized
  - Запрос с невалидным токеном → 401 Unauthorized

- [ ] **Доступ к пользователю в контроллерах**
  - `$this->getUser()` возвращает OctowireUser
  - Claims доступны через `$user->getClaims()`
  - Роли доступны через `$user->getRoles()`

- [ ] **Access Control**
  - `#[IsGranted('ROLE_USER')]` работает корректно
  - `#[IsGranted('ROLE_ADMIN')]` проверяет роли
  - Запрещенный доступ возвращает 403

- [ ] **Multi-project support**
  - Токены для разных проектов обрабатываются корректно
  - Project ID извлекается из токена или используется default
  - Правильный AuthClient используется для каждого проекта

### 3. Integration тесты (с реальным Auth Service) - опционально

**Назначение:** End-to-end тестирование с реальным Auth Service через TCP/JATP.

**Требования:**
- Запущенный Auth Service (локально или в Docker)
- Redis для Auth Service
- Реальные JWT токены

**Тесты:**

- [ ] **Реальное TCP соединение**
  - Успешное подключение к Auth Service
  - Валидация токенов через реальный сервис
  - Обработка сетевых ошибок

- [ ] **End-to-end аутентификация**
  - Выдача токена через Auth Service
  - Валидация токена через Bundle
  - Полный цикл: IssueToken → ValidateToken → Authenticate

- [ ] **Производительность**
  - Время валидации токена
  - Время создания пользователя
  - Кэширование ключей работает

## 🛠 Технические детали

### TestKernel для изоляции тестов

```php
// tests/Fixtures/TestKernel.php

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Fixtures;

use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Config\Loader\LoaderInterface;

class TestKernel extends Kernel
{
    public function registerBundles(): iterable
    {
        return [
            new \Symfony\Bundle\FrameworkBundle\FrameworkBundle(),
            new \Symfony\Bundle\SecurityBundle\SecurityBundle(),
            new \Kabiroman\Octawire\AuthService\Bundle\OctawireAuthBundle(),
        ];
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(__DIR__ . '/config/test_services.yaml');
    }

    public function getProjectDir(): string
    {
        return __DIR__ . '/..';
    }
}
```

### Базовый KernelTestCase

```php
// tests/Functional/KernelTestCase.php

namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Functional;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase as BaseKernelTestCase;
use Symfony\Component\HttpKernel\KernelInterface;
use Kabiroman\Octawire\AuthService\Bundle\Tests\Fixtures\TestKernel;

abstract class KernelTestCase extends BaseKernelTestCase
{
    protected static function getKernelClass(): string
    {
        return TestKernel::class;
    }

    protected static function createKernel(array $options = []): KernelInterface
    {
        return new TestKernel(
            $options['environment'] ?? 'test',
            $options['debug'] ?? true
        );
    }
}
```

### Тестовая конфигурация Bundle

```yaml
# tests/Fixtures/config/test_bundle.yaml

octawire_auth:
    default_project: 'test-project'
    projects:
        test-project:
            transport: 'tcp'
            tcp:
                host: 'localhost'
                port: 50052
                persistent: false  # Отключено для тестов
                tls:
                    enabled: false
            project_id: 'test-project'
            retry:
                max_attempts: 1  # Минимум для быстрых тестов
            key_cache:
                driver: 'memory'
                ttl: 60
```

### Тестовая Security конфигурация

```yaml
# tests/Fixtures/config/test_security.yaml

security:
    firewalls:
        test:
            pattern: ^/test/
            stateless: true
            custom_authenticators:
                - octawire_auth.authenticator
```

## 📦 Зависимости для тестирования

### Требуемые пакеты (require-dev)

```json
{
    "require-dev": {
        "phpunit/phpunit": "^10.0",
        "symfony/phpunit-bridge": "^7.0",
        "symfony/browser-kit": "^7.0",  // Для HTTP тестов
        "symfony/css-selector": "^7.0"  // Для BrowserKit (опционально)
    }
}
```

## 🚀 План реализации

### Этап 1: Service Auth покрытие

- [ ] Расширить `TokenValidatorTest` сценариями service-token: успех, истечение, неверный secret, неразрешённый сервис.
- [ ] Добавить интеграционный тест в `otus_project2`, фиксирующий, что удалённая валидация работает только при корректном `service_auth`.

### Этап 2: Local validation + cache

- [ ] Рефактор `LocalTokenValidator` (инъекция кэша) для тестирования ресеша ключей.
- [ ] Написать тесты, что ключ берётся из кэша, сбрасывается по TTL, повторно запрашивается.

### Этап 3: Multi-project сценарии

- [ ] Добавить фикстуры с несколькими проектами и влиянием на `default_project`.
- [ ] Написать функциональные тесты, выпускающие токены с разными `project_id` и проверяющие whitelist/отклонения.

### Этап 4: TLS / mTLS

- [ ] Подготовить self-signed сертификаты для тестов.
- [ ] Добавить e2e тест (можно пометить как slow) с включённым TLS, проверить ошибки при отсутствии cert/secret.

### Этап 5: Документация и метрики

- [ ] Обновить README/Protocol описанием новых сценариев и запусков TLS тестов.
- [ ] Повысить покрытия >90% по unit и зафиксировать команды запуска (coverage-html/coverage-text).

## ✅ Критерии готовности

- [ ] Unit покрытие > 90% (включая TokenValidator service-token, LocalTokenValidator cache).
- [ ] Functional тесты закрывают multi-project/TLS/service-auth комбинации.
- [ ] Интеграционный e2e сценарий с Auth Service проходит для remote/local/hybrid.
- [ ] Документация в README/Protocol синхронизирована с фактическим покрытием.

## 📝 Примеры тестов

### Пример: BundleConfigurationTest

```php
namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Functional;

use Kabiroman\Octawire\AuthService\Bundle\Factory\AuthClientFactory;
use Kabiroman\Octawire\AuthService\Bundle\Service\TokenValidator;
use Kabiroman\Octawire\AuthService\Bundle\Security\OctowireTokenAuthenticator;
use PHPUnit\Framework\TestCase;

class BundleConfigurationTest extends KernelTestCase
{
    public function testBundleRegistersServices(): void
    {
        self::bootKernel(['test_case' => 'Bundle']);
        
        $container = self::getContainer();
        
        $this->assertTrue($container->has('octawire_auth.client_factory'));
        $this->assertTrue($container->has('octawire_auth.token_validator'));
        $this->assertTrue($container->has('octawire_auth.authenticator'));
        $this->assertTrue($container->has('octawire_auth.user_provider'));
    }

    public function testAuthClientCreatedForProject(): void
    {
        self::bootKernel(['test_case' => 'Bundle']);
        
        $container = self::getContainer();
        $factory = $container->get('octawire_auth.client_factory');
        
        $this->assertInstanceOf(AuthClientFactory::class, $factory);
        
        $client = $factory->getClient('test-project');
        $this->assertNotNull($client);
    }
}
```

### Пример: AuthenticatorIntegrationTest

```php
namespace Kabiroman\Octawire\AuthService\Bundle\Tests\Functional;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class AuthenticatorIntegrationTest extends WebTestCase
{
    public function testAuthenticatorValidatesValidToken(): void
    {
        $client = static::createClient();
        
        // Создаем валидный JWT токен (через мок или реальный)
        $token = $this->createValidToken();
        
        $client->request('GET', '/test/protected', [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $token
        ]);
        
        $this->assertResponseIsSuccessful();
        $this->assertTrue($client->getContainer()->get('security.token_storage')->getToken() !== null);
    }

    public function testAuthenticatorRejectsInvalidToken(): void
    {
        $client = static::createClient();
        
        $client->request('GET', '/test/protected', [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer invalid-token'
        ]);
        
        $this->assertResponseStatusCodeSame(401);
    }
}
```

## 🔍 Покрытие тестами

### Целевое покрытие

- **Unit тесты**: > 90% покрытие всех компонентов
- **Functional тесты**: Все публичные методы Bundle
- **Integration тесты**: Основные сценарии использования

### Метрики

```bash
# Запуск тестов с покрытием
vendor/bin/phpunit --coverage-html coverage/
vendor/bin/phpunit --coverage-text
```

## 📚 Дополнительные ресурсы

- [Symfony Testing Guide](https://symfony.com/doc/current/testing.html)
- [Symfony Bundle Testing](https://symfony.com/doc/current/bundles/best_practices.html#testing)
- [PHPUnit Documentation](https://phpunit.de/documentation.html)

---

**Последнее обновление:** 2025-11-25

