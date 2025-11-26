# Руководство по тестированию Octawire Auth Service Symfony Bundle

Документ описывает всю процедуру проверки бандла: от локальных юнит‑тестов до интеграционных прогонов на `otus_project2` с запущенным Go‑сервисом.

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

## 5. Полезные команды

```bash
# Запустить только тесты TLS
./bin/phpunit --filter testProtectedEndpointFailsWithInvalidTlsConfiguration tests/Integration/BundleIntegrationTest.php

# Прогнать юнит-тесты с Xdebug coverage
XDEBUG_MODE=coverage vendor/bin/phpunit --testsuite unit --coverage-text
```

---

Поддерживайте этот документ актуальным при добавлении новых тестовых сценариев или изменении инфраструктуры. Questions → `TESTING_PLAN.md` (описание стратегий) и `docs/KNOWN_ISSUES.md` (известные проблемы сервиса).


