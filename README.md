# Зарплата: учёт и расчёт — онлайн-версия

## Быстрый старт (локально)

1. Установите Node.js 18+ с https://nodejs.org
2. Распакуйте архив
3. В папке проекта выполните: `npm install`
4. Создайте базу PostgreSQL и загрузите схему: `psql -d salary_db -f db.sql`
5. Скопируйте `.env.example` в `.env` и заполните параметры
6. Запустите: `npm start`
7. Откройте http://localhost:3000
8. Вход: ADMIN / ADMIN

## Размещение на Timeweb Cloud

1. Зарегистрируйтесь на https://timeweb.cloud
2. Создайте базу данных PostgreSQL
3. Выполните db.sql через phpPgAdmin
4. Создайте приложение Node.js
5. Загрузите все файлы
6. Добавьте переменные окружения: DATABASE_URL, SESSION_SECRET, PORT=3000
7. Запустите приложение
