# 📊 BudgetWise

**BudgetWise** — персональное приложение для управления личными финансами. Система включает учёт транзакций, установку бюджетов, целей накоплений, управление пользователями и многое другое.

---

## 🚀 Возможности

- 🔐 Регистрация и вход с JWT-аутентификацией
- 👤 Профиль пользователя и настройки
- 💰 Учёт доходов и расходов по категориям
- 📊 Планирование бюджета с лимитами
- 🎯 Постановка целей накоплений
- 🌍 Выбор валют и языка интерфейса
- 📈 Просмотр и фильтрация транзакций
- 🧪 Базовое покрытие unit-тестами

---

## 🧱 Структура проекта

```bash
budgetwise/
├── microservices/
│   └── main_app/
│       ├── api/                   # Роуты, схемы, сервисы, репозитории
│       ├── core/                  # Настройки и безопасность
│       ├── main.py                # Точка входа FastAPI
│       ├── Dockerfile
│       └── requirements.txt
├── libs/                          # Общие библиотеки (ошибки, утилиты, логгер)
├── migrations/                    # Alembic миграции
├── environments/                  # Файлы .env
├── docker-compose.yml
└── README.md
```

---

## ⚙️ Стек технологий

- **FastAPI** — backend-фреймворк
- **PostgreSQL** — основная база данных
- **SQLAlchemy** — ORM
- **Alembic** — миграции
- **Docker / docker-compose** — контейнеризация
- **Pytest** — тестирование
- **Pydantic** — валидация схем

---

## 🔧 Быстрый старт

```bash
git clone https://github.com/your-username/budgetwise.git
cd budgetwise
cp environments/postgres.example.env environments/app.env
docker-compose up --build
```

---

## 📂 Примеры API (в разработке)

- `POST /auth/register` — регистрация
- `POST /auth/login` — авторизация
- `GET /transactions` — список транзакций
- `POST /budgets` — создать бюджет
- `GET /saving-goals` — цели накоплений

---

## 🧑‍💻 Автор

**Акжан Матаев**  
📫 Email: _укажи свой email_  
🐙 GitHub: [github.com/your-username](https://github.com/your-username)

---

## ⚠️ Статус

Проект находится в активной разработке 🛠️