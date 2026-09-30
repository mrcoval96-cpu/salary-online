-- Базовая схема "Зарплата: учёт и расчёт"
-- Безопасна для повторного запуска: не удаляет существующие данные.
-- ADMIN не создаётся здесь: приложение создаёт его через initAdmin() при необходимости.

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    login VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    fio VARCHAR(255) NOT NULL,
    phone VARCHAR(50) DEFAULT '',
    email TEXT,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    role VARCHAR(50) DEFAULT '',
    organization VARCHAR(255) DEFAULT '',
    object_name VARCHAR(255) DEFAULT '',
    role_history TEXT DEFAULT '[]',
    permission_overrides JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_login_at TIMESTAMP,
    login_count INTEGER NOT NULL DEFAULT 0,
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
    employment_status TEXT NOT NULL DEFAULT 'working',
    hr_profile JSONB NOT NULL DEFAULT '{}'::jsonb,
    photo_data TEXT NOT NULL DEFAULT '',
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
    full_name TEXT NOT NULL DEFAULT '',
    inn TEXT NOT NULL DEFAULT '',
    kpp TEXT NOT NULL DEFAULT '',
    ogrn TEXT NOT NULL DEFAULT '',
    legal_address TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    postal_address TEXT NOT NULL DEFAULT '',
    director_fio TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    website TEXT NOT NULL DEFAULT '',
    bank_name TEXT NOT NULL DEFAULT '',
    bik TEXT NOT NULL DEFAULT '',
    settlement_account TEXT NOT NULL DEFAULT '',
    correspondent_account TEXT NOT NULL DEFAULT '',
    contacts TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS salary_records (
    id SERIAL PRIMARY KEY,
    employee_fio VARCHAR(255) NOT NULL,
    object_name VARCHAR(255) DEFAULT '',
    organization TEXT NOT NULL DEFAULT '',
    month VARCHAR(20) DEFAULT '',
    year VARCHAR(10) DEFAULT '',
    charge_date DATE,
    hour_rate NUMERIC(10,2) DEFAULT 0,
    hours NUMERIC(10,2) DEFAULT 0,
    per_diem_days NUMERIC(10,2) DEFAULT 0,
    per_diem_rate NUMERIC(10,2) DEFAULT 0,
    extra_charges TEXT DEFAULT '[]',
    payments TEXT DEFAULT '[]',
    total NUMERIC(12,2) DEFAULT 0,
    paid NUMERIC(12,2) DEFAULT 0,
    deleted_at TIMESTAMP,
    deleted_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS action_log (
    id SERIAL PRIMARY KEY,
    user_login VARCHAR(100) DEFAULT '',
    action TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS object_responsibles (
    object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (object_id, employee_id)
);

CREATE TABLE IF NOT EXISTS object_user_responsibles (
    object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (object_id, user_id)
);

CREATE TABLE IF NOT EXISTS organization_aliases (
    alias TEXT PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS closed_salary_periods (
    month TEXT NOT NULL,
    year TEXT NOT NULL,
    organization TEXT NOT NULL DEFAULT '',
    closed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_by TEXT
);

CREATE TABLE IF NOT EXISTS automatic_backups (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS security_log (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event TEXT NOT NULL,
    user_login TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    success BOOLEAN NOT NULL DEFAULT FALSE,
    details TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS email_codes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    purpose TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS employee_balances (
    id SERIAL PRIMARY KEY,
    employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    employee_fio TEXT NOT NULL,
    balance_date DATE NOT NULL,
    amount NUMERIC(14,2) NOT NULL DEFAULT 0,
    direction TEXT NOT NULL DEFAULT 'company_to_employee',
    comment TEXT NOT NULL DEFAULT '',
    created_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS bank_statement_payments (
    id SERIAL PRIMARY KEY,
    employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    employee_fio TEXT NOT NULL,
    bank TEXT NOT NULL,
    company_account TEXT NOT NULL DEFAULT '',
    transaction_date DATE NOT NULL,
    amount NUMERIC(14,2) NOT NULL,
    document_number TEXT NOT NULL DEFAULT '',
    recipient_account TEXT NOT NULL DEFAULT '',
    counterparty TEXT NOT NULL DEFAULT '',
    purpose TEXT NOT NULL DEFAULT '',
    transaction_key TEXT NOT NULL UNIQUE,
    source_filename TEXT NOT NULL DEFAULT '',
    allocations JSONB NOT NULL DEFAULT '[]'::jsonb,
    imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    imported_by TEXT
);

-- Совместимость с ранними версиями базы.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS permission_overrides JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS login_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE employees ADD COLUMN IF NOT EXISTS employment_status TEXT NOT NULL DEFAULT 'working';
ALTER TABLE employees ADD COLUMN IF NOT EXISTS hr_profile JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS photo_data TEXT NOT NULL DEFAULT '';

ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS organization TEXT NOT NULL DEFAULT '';
ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS charge_date DATE;
ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS deleted_by TEXT;

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS full_name TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS inn TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS kpp TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS ogrn TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS legal_address TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS postal_address TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS director_fio TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS phone TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS email TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS website TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS bank_name TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS bik TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS settlement_account TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS correspondent_account TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ALTER COLUMN address TYPE TEXT;
ALTER TABLE organizations ALTER COLUMN contacts TYPE TEXT;

ALTER TABLE closed_salary_periods ADD COLUMN IF NOT EXISTS organization TEXT NOT NULL DEFAULT '';
ALTER TABLE employee_balances ADD COLUMN IF NOT EXISTS direction TEXT NOT NULL DEFAULT 'company_to_employee';
ALTER TABLE bank_statement_payments ADD COLUMN IF NOT EXISTS allocations JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique
    ON users(lower(email)) WHERE email IS NOT NULL AND trim(email) <> '';
CREATE INDEX IF NOT EXISTS idx_salary_records_organization
    ON salary_records(lower(trim(organization)));
CREATE INDEX IF NOT EXISTS idx_salary_records_deleted_at
    ON salary_records(deleted_at);
CREATE INDEX IF NOT EXISTS idx_object_responsibles_employee
    ON object_responsibles(employee_id);
CREATE INDEX IF NOT EXISTS idx_object_user_responsibles_user
    ON object_user_responsibles(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_organization_aliases_norm
    ON organization_aliases(lower(trim(alias)));
CREATE UNIQUE INDEX IF NOT EXISTS idx_closed_salary_periods_scope
    ON closed_salary_periods(month,year,organization);
CREATE INDEX IF NOT EXISTS idx_security_log_created_at
    ON security_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_log_event
    ON security_log(event);
CREATE INDEX IF NOT EXISTS idx_email_codes_lookup
    ON email_codes(lower(email), purpose, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_employee_balances_employee_date
    ON employee_balances(lower(employee_fio), balance_date DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_bank_statement_payments_employee_date
    ON bank_statement_payments(lower(employee_fio), transaction_date, id);
CREATE INDEX IF NOT EXISTS idx_bank_statement_payments_transaction_key
    ON bank_statement_payments(transaction_key);
CREATE INDEX IF NOT EXISTS idx_organizations_inn
    ON organizations(inn) WHERE trim(inn)<>'';
CREATE INDEX IF NOT EXISTS idx_organizations_ogrn
    ON organizations(ogrn) WHERE trim(ogrn)<>'';
