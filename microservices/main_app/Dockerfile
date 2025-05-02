# 1. Используем лёгкий образ Python
FROM python:3.11-slim

# 2. Устанавливаем рабочую директорию
WORKDIR /app

# 3. Копируем зависимости
COPY requirements.txt .

# 4. Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# 5. Копируем весь код сервиса
COPY . .

ENV PYTHONPATH="/app"

# 6. Открываем порт
EXPOSE 8880



CMD ["uvicorn", "main_app.main:app", "--host", "0.0.0.0", "--port", "8880", "--reload"]
