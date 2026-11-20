# Лабораторная работа 5. Вариант 22 — Распределение мест в общежитии
## JWT Access/Refresh и управление сессиями

Проект представляет собой бэкенд-сервис для управления заселением в студенческое общежитие. В пятой лабораторной работе реализована аутентификация на основе **JWT (JSON Web Token)** с разделением на короткоживущие **access-токены** и долгоживущие **refresh-токены**, серверный учёт сессий, ротация refresh-токенов и защита от компрометации (Reuse Detection).

---

## Стек технологий
- **Java 17**
- **Spring Boot 3.2.5** (Spring Web, Spring Data JPA, Spring Security, Validation)
- **Spring Security 6+** (Stateless, OncePerRequestFilter, Method Security `@PreAuthorize`)
- **JJWT 0.13.0** (`jjwt-api`, `jjwt-impl`, `jjwt-jackson`)
- **PostgreSQL 18**
- **Lombok**
- **Maven**

---

## Архитектура безопасности и реализация (Лабораторная работа 5)

### 1. Сущность `UserSession` и серверный учёт сессий
Для хранения состояния сессий и контроля жизненного цикла refresh-токенов создана таблица `user_sessions` и JPA-сущность `UserSession`:

| Поле / Колонка | Тип | Назначение / Ограничения |
| :--- | :--- | :--- |
| `id` | `Long` (BIGSERIAL) | Первичный ключ сессии |
| `user` (`user_id`) | `User` (FK) | Владелец сессии (связь с `users`) |
| `refreshTokenId` (`refresh_token_id`) | `String` | Уникальный идентификатор refresh-токена (`jti` из JWT), `UNIQUE NOT NULL` |
| `status` (`status`) | `SessionStatus` | Текущее состояние сессии (строковый enum) |
| `deviceId` (`device_id`) | `String` | Метка клиента/устройства (допускается `null`) |
| `createdAt` (`created_at`) | `Instant` | Дата и время выдачи пары |
| `expiresAt` (`expires_at`) | `Instant` | Срок истечения refresh-токена |

**Статусы сессии (`SessionStatus`):**
- **`ACTIVE`** — refresh-токен выдан, ещё не использован и не отозван;
- **`USED`** — refresh-токен успешно применён для получения новой пары (ротация);
- **`REVOKED`** — сессия аннулирована (в том числе при обнаружении попытки повторного использования).

---

### 2. Генерация и валидация JWT (`JwtTokenProvider`)
Используется алгоритм симметричной подписи **HMAC-SHA-256 (HS256)** с 256-битным секретным ключом.

- **Access-токен:**
  - Время жизни: **15 минут** (`jwt.accessExpiration=900000`).
  - Claims: `sub` (email пользователя), `auth` (роли/полномочия), `type: "access"`, `iat`, `exp`.
  - Предназначение: доступ к защищённым ресурсам через заголовок `Authorization: Bearer <token>`.
- **Refresh-токен:**
  - Время жизни: **7 дней** (`jwt.refreshExpiration=604800000`).
  - Claims: `sub` (email), `jti` (случайный UUID идентификатор сессии), `type: "refresh"`, `iat`, `exp`.
  - Предназначение: исключительно для обновления пары токенов через эндпоинт `/api/auth/refresh`.

---

### 3. Механизм ротации и детектирование повторного использования (Reuse Detection)
1. **Выдача пары (Login / Register):**
   - Генерируются новые access- и refresh-токены.
   - В БД сохраняется запись `UserSession` со статусом `ACTIVE` и `refreshTokenId = jti`.
2. **Обновление пары (Refresh):**
   - Токен валидируется: проверяется подпись, срок действия и claim `type == "refresh"`.
   - По `jti` находится соответствующая сессия в БД.
   - **Нормальный сценарий (сессия `ACTIVE`):** статус сессии переводится в `USED`, создаётся и возвращается совершенно новая пара токенов с новой записью сессии `ACTIVE`.
   - **Обнаружение компрометации (сессия уже `USED`):** если клиент повторно предъявляет уже использованный токен, система фиксирует попытку перехвата/повторного использования (Token Reuse) и **немедленно отзывает (`REVOKED`) все активные сессии данного пользователя**, возвращая отказ **401 Unauthorized**.
   - **Отозванная сессия (`REVOKED`):** запрос немедленно отклоняется с ошибкой **401 Unauthorized**.

---

### 4. Фильтр безопасности (`JwtTokenFilter`) и `SecurityConfig`
- Приложение работает в режиме **`SessionCreationPolicy.STATELESS`** — HTTP-сессии на сервере не создаются.
- Поскольку токен передаётся клиентом явно в заголовке `Authorization`, защита **CSRF отключена**.
- `JwtTokenFilter` извлекает заголовок `Authorization: Bearer <token>`, проверяет валидность access-токена, тип `type == "access"` и наполняет `SecurityContextHolder` объектом `Authentication`.
- Эндпоинты `/api/auth/login`, `/api/auth/register`, `/api/auth/refresh` исключены из фильтрации (`shouldNotFilter`), чтобы просроченный access-токен не блокировал обновление или вход.

---

### 5. Контракт эндпоинтов аутентификации

| Метод и URL | Назначение | Тело запроса | Успешный ответ | Коды ошибок |
| :--- | :--- | :--- | :--- | :--- |
| `POST /api/auth/register` | Регистрация нового студента и выдача пары | `fullName`, `email`, `password` | `201 Created` (`email`, `accessToken`, `refreshToken`) | 400 (валидация), 409 (дубликат email) |
| `POST /api/auth/login` | Вход по паролю | `email`, `password`, `deviceId` (opt) | `200 OK` (`email`, `accessToken`, `refreshToken`) | 400 (пустые поля), 401 (неверный логин/пароль) |
| `POST /api/auth/refresh` | Обновление пары токенов | `refreshToken` | `200 OK` (`email`, `accessToken`, `refreshToken`) | 400 (нет токена), 401 (недействителен, истек, повторное использование) |

---

## Тестовые учетные записи (после запуска `init-db.sql`)

Пароль для всех тестовых аккаунтов: **`Password123!`**

| Email | Роль | Статус аккаунта | Описание |
| :--- | :--- | :--- | :--- |
| `vasiliev@university.ru` | `ADMIN` | Активен | Администратор (полный доступ) |
| `ivanov@university.ru` | `STUDENT` | Активен | Студент (id = 1) |
| `petrov@university.ru` | `STUDENT` | Активен | Студент (id = 2) |
| `sidorova@university.ru` | `STUDENT` | Активен | Студент (id = 3) |
| `smirnov@university.ru` | `STUDENT` | **Заблокирован** | Для проверки отказа входа (401) |

---

## Запуск и проверка

### 1. База данных
```bash
psql -U postgres -h localhost -p 5432 -f init-db.sql
```
Скрипт создает таблицы `users`, `rooms`, `housing_applications`, `residence_contracts`, `room_transfer_requests`, а также новую таблицу `user_sessions`.

### 2. Сборка и компиляция
```bash
mvn clean compile
```

### 3. Запуск тестов
```bash
mvn test
```
Тесты проверяют:
- Регистрацию и валидацию данных;
- Выдачу пары JWT при регистрации и логине;
- Валидацию access-токена при доступе к защищённым ресурсам;
- Успешную ротацию токенов через `/api/auth/refresh`;
- Срабатывание механизма Reuse Detection (повторное использование refresh-токена вызывает 401 и отзыв сессий);
- Ролевую изоляцию и проверки безопасности `@PreAuthorize`.

### 4. Тестирование через `requests.http`
В файле `requests.http` содержатся готовые запросы для проверки цепочки входа, обновления пары и проверки доступа с Bearer-токеном.
