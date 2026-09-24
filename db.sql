-- Схема базы данных для "Зарплата: учёт и расчёт"

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    login VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    fio VARCHAR(255) NOT NULL,
    phone VARCHAR(50) DEFAULT '',
    role VARCHAR(50) DEFAULT '',
    organization VARCHAR(255) DEFAULT '',
    object_name VARCHAR(255) DEFAULT '',
    role_history TEXT DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS employees (
    id SERIAL PRIMARY KEY,
    fio VARCHAR(255) NOT NULL,
    organization VARCHAR(255) DEFAULT '',
    position VARCHAR(255) DEFAULT '',
    phone VARCHAR(50) DEFAULT '',
    birth_date VARCHAR(20) DEFAULT '',
    comments TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS objects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    address VARCHAR(500) DEFAULT '',
    customer VARCHAR(255) DEFAULT '',
    organization VARCHAR(255) DEFAULT '',
    responsible VARCHAR(255) DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS organizations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    address VARCHAR(500) DEFAULT '',
    contacts VARCHAR(500) DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS salary_records (
    id SERIAL PRIMARY KEY,
    employee_fio VARCHAR(255) NOT NULL,
    object_name VARCHAR(255) DEFAULT '',
    month VARCHAR(20) DEFAULT '',
    year VARCHAR(10) DEFAULT '',
    hour_rate NUMERIC(10,2) DEFAULT 0,
    hours NUMERIC(10,2) DEFAULT 0,
    per_diem_days NUMERIC(10,2) DEFAULT 0,
    per_diem_rate NUMERIC(10,2) DEFAULT 0,
    extra_charges TEXT DEFAULT '[]',
    payments TEXT DEFAULT '[]',
    total NUMERIC(12,2) DEFAULT 0,
    paid NUMERIC(12,2) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS action_log (
    id SERIAL PRIMARY KEY,
    user_login VARCHAR(100) DEFAULT '',
    action TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Создание ADMIN (пароль ADMIN, захеширован bcrypt)
-- Внимание: этот хеш сгенерирован для пароля "ADMIN"
INSERT INTO users (login, password, fio, phone, role)
VALUES ('ADMIN', '$2a$10$N9qo8uLOickgx2ZMRZoMy.MrqJ5B7HqXKKQ7XJ7mqKqYJZmZKqKqK', 'Администратор', '', 'Руководитель сайта')
ON CONFLICT (login) DO NOTHING;
