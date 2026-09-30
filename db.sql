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


-- === 152-FZ compliance baseline ===
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS data_region TEXT NOT NULL DEFAULT 'RU';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS closed_at TIMESTAMP;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS retention_profile_id INTEGER;

ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMP;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL;
ALTER TABLE objects ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL;
ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL;
ALTER TABLE employee_balances ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL;
ALTER TABLE bank_statement_payments ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_employees_tenant_id ON employees(tenant_id);
CREATE INDEX IF NOT EXISTS idx_objects_tenant_id ON objects(tenant_id);
CREATE INDEX IF NOT EXISTS idx_salary_records_tenant_id ON salary_records(tenant_id);
CREATE INDEX IF NOT EXISTS idx_employee_balances_tenant_id ON employee_balances(tenant_id);
CREATE INDEX IF NOT EXISTS idx_bank_statement_payments_tenant_id ON bank_statement_payments(tenant_id);

CREATE TABLE IF NOT EXISTS processing_purposes (
  purpose_id TEXT PRIMARY KEY,
  description TEXT NOT NULL,
  legal_basis TEXT NOT NULL DEFAULT '',
  categories JSONB NOT NULL DEFAULT '[]'::jsonb,
  retention_rule TEXT NOT NULL DEFAULT '',
  allowed_recipients JSONB NOT NULL DEFAULT '[]'::jsonb,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS legal_documents (
  id BIGSERIAL PRIMARY KEY,
  doc_type TEXT NOT NULL,
  version TEXT NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  published_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE(doc_type,version)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_legal_documents_one_active ON legal_documents(doc_type) WHERE active=TRUE;
CREATE TABLE IF NOT EXISTS consents (
  consent_id BIGSERIAL PRIMARY KEY,
  tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  subject_ref TEXT NOT NULL,
  purpose_id TEXT NOT NULL,
  document_type TEXT NOT NULL,
  document_version TEXT NOT NULL,
  document_hash TEXT NOT NULL,
  given_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  channel TEXT NOT NULL DEFAULT 'web',
  source_form TEXT NOT NULL DEFAULT '',
  method TEXT NOT NULL DEFAULT 'checkbox',
  evidence_ip TEXT NOT NULL DEFAULT '',
  evidence_user_agent TEXT NOT NULL DEFAULT '',
  withdrawn_at TIMESTAMP,
  withdrawal_channel TEXT NOT NULL DEFAULT '',
  withdrawal_reason TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'given',
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_consents_subject ON consents(subject_ref,given_at DESC);
CREATE INDEX IF NOT EXISTS idx_consents_tenant ON consents(tenant_id,given_at DESC);
CREATE TABLE IF NOT EXISTS marketing_suppression (
  id BIGSERIAL PRIMARY KEY,
  normalized_address TEXT NOT NULL UNIQUE,
  source_consent_id BIGINT REFERENCES consents(consent_id) ON DELETE SET NULL,
  suppressed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reason TEXT NOT NULL DEFAULT 'withdrawal'
);
CREATE TABLE IF NOT EXISTS data_subject_requests (
  request_id BIGSERIAL PRIMARY KEY,
  tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
  requester_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  subject_ref TEXT NOT NULL,
  request_type TEXT NOT NULL,
  received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  identity_status TEXT NOT NULL DEFAULT 'account_authenticated',
  due_at TIMESTAMP NOT NULL,
  status TEXT NOT NULL DEFAULT 'received',
  details TEXT NOT NULL DEFAULT '',
  decision TEXT NOT NULL DEFAULT '',
  extension_reason TEXT NOT NULL DEFAULT '',
  extended_at TIMESTAMP,
  completed_at TIMESTAMP,
  created_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_dsar_tenant_due ON data_subject_requests(tenant_id,status,due_at);
CREATE TABLE IF NOT EXISTS audit_events (
  event_id BIGSERIAL PRIMARY KEY,
  occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  actor_type TEXT NOT NULL DEFAULT 'user',
  tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  object_type TEXT NOT NULL DEFAULT '',
  object_id TEXT NOT NULL DEFAULT '',
  result TEXT NOT NULL DEFAULT '',
  source_ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  correlation_id TEXT NOT NULL DEFAULT '',
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_events(tenant_id,occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action_time ON audit_events(action,occurred_at DESC);
CREATE TABLE IF NOT EXISTS incidents (
  incident_id BIGSERIAL PRIMARY KEY,
  severity TEXT NOT NULL,
  detected_at TIMESTAMP NOT NULL,
  confirmed_at TIMESTAMP,
  tenant_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  data_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
  subject_count_estimate INTEGER,
  description TEXT NOT NULL DEFAULT '',
  timeline JSONB NOT NULL DEFAULT '[]'::jsonb,
  notification_status JSONB NOT NULL DEFAULT '{}'::jsonb,
  due_24h TIMESTAMP,
  due_72h TIMESTAMP,
  root_cause TEXT NOT NULL DEFAULT '',
  corrective_actions TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_incidents_status_due ON incidents(status,due_24h,due_72h);
CREATE TABLE IF NOT EXISTS admin_access_sessions (
  id BIGSERIAL PRIMARY KEY,
  requester_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  approver_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  tenant_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT '',
  ticket_id TEXT NOT NULL DEFAULT '',
  starts_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ends_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP,
  actions_link TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS exports (
  id BIGSERIAL PRIMARY KEY,
  tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
  requester_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  scope TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  file_ref TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP,
  downloaded_at TIMESTAMP,
  status TEXT NOT NULL DEFAULT 'created'
);
CREATE TABLE IF NOT EXISTS deletion_jobs (
  id BIGSERIAL PRIMARY KEY,
  tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
  subject_ref TEXT NOT NULL,
  legal_reason TEXT NOT NULL,
  stores_targeted JSONB NOT NULL DEFAULT '[]'::jsonb,
  started_at TIMESTAMP,
  completed_at TIMESTAMP,
  result TEXT NOT NULL DEFAULT '',
  evidence_ref TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'queued',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS retention_rules (
  id BIGSERIAL PRIMARY KEY,
  tenant_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
  data_category TEXT NOT NULL,
  purpose_id TEXT NOT NULL,
  duration_rule TEXT NOT NULL,
  trigger_event TEXT NOT NULL,
  action TEXT NOT NULL,
  exception_hold TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS subprocessors_integrations (
  id BIGSERIAL PRIMARY KEY,
  tenant_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
  vendor TEXT NOT NULL,
  country TEXT NOT NULL,
  data_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
  purpose TEXT NOT NULL,
  endpoint TEXT NOT NULL DEFAULT '',
  dpa_status TEXT NOT NULL DEFAULT '',
  transfer_status TEXT NOT NULL DEFAULT '',
  approved_at TIMESTAMP,
  owner TEXT NOT NULL DEFAULT '',
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO processing_purposes(purpose_id,description,legal_basis,categories,retention_rule,allowed_recipients)
VALUES
  ('account_processing','Регистрация и обслуживание учётной записи','согласие/договор/иное применимое основание','["contact","account","security"]'::jsonb,'до достижения цели и применимых сроков','["authorized_staff"]'::jsonb),
  ('service_terms','Фиксация принятия пользовательского соглашения','договор','["account"]'::jsonb,'срок договора + применимый срок доказательств','["authorized_staff"]'::jsonb),
  ('marketing','Рекламные и маркетинговые сообщения','отдельное предварительное согласие','["email","phone"]'::jsonb,'до отзыва согласия','["authorized_marketing"]'::jsonb)
ON CONFLICT(purpose_id) DO NOTHING;


-- Автоматическое поддержание tenant_id для tenant-owned сущностей.
CREATE OR REPLACE FUNCTION set_tenant_id_from_organization() RETURNS trigger AS $$
BEGIN
  IF trim(COALESCE(NEW.organization,''))='' THEN
    NEW.tenant_id=NULL;
  ELSE
    SELECT id INTO NEW.tenant_id
    FROM organizations
    WHERE lower(trim(name))=lower(trim(NEW.organization))
    ORDER BY id LIMIT 1;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_users_tenant_from_org ON users;
CREATE TRIGGER trg_users_tenant_from_org BEFORE INSERT OR UPDATE OF organization ON users FOR EACH ROW EXECUTE FUNCTION set_tenant_id_from_organization();
DROP TRIGGER IF EXISTS trg_employees_tenant_from_org ON employees;
CREATE TRIGGER trg_employees_tenant_from_org BEFORE INSERT OR UPDATE OF organization ON employees FOR EACH ROW EXECUTE FUNCTION set_tenant_id_from_organization();
DROP TRIGGER IF EXISTS trg_objects_tenant_from_org ON objects;
CREATE TRIGGER trg_objects_tenant_from_org BEFORE INSERT OR UPDATE OF organization ON objects FOR EACH ROW EXECUTE FUNCTION set_tenant_id_from_organization();
DROP TRIGGER IF EXISTS trg_salary_records_tenant_from_org ON salary_records;
CREATE TRIGGER trg_salary_records_tenant_from_org BEFORE INSERT OR UPDATE OF organization ON salary_records FOR EACH ROW EXECUTE FUNCTION set_tenant_id_from_organization();

CREATE OR REPLACE FUNCTION set_tenant_id_from_employee() RETURNS trigger AS $$
BEGIN
  IF NEW.employee_id IS NULL THEN
    NEW.tenant_id=NULL;
  ELSE
    SELECT tenant_id INTO NEW.tenant_id FROM employees WHERE id=NEW.employee_id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_employee_balances_tenant_from_employee ON employee_balances;
CREATE TRIGGER trg_employee_balances_tenant_from_employee BEFORE INSERT OR UPDATE OF employee_id ON employee_balances FOR EACH ROW EXECUTE FUNCTION set_tenant_id_from_employee();
DROP TRIGGER IF EXISTS trg_bank_statement_payments_tenant_from_employee ON bank_statement_payments;
CREATE TRIGGER trg_bank_statement_payments_tenant_from_employee BEFORE INSERT OR UPDATE OF employee_id ON bank_statement_payments FOR EACH ROW EXECUTE FUNCTION set_tenant_id_from_employee();

UPDATE users u SET tenant_id=o.id FROM organizations o
WHERE u.tenant_id IS NULL AND trim(COALESCE(u.organization,''))<>'' AND lower(trim(u.organization))=lower(trim(o.name));
UPDATE employees e SET tenant_id=o.id FROM organizations o
WHERE e.tenant_id IS NULL AND trim(COALESCE(e.organization,''))<>'' AND lower(trim(e.organization))=lower(trim(o.name));
UPDATE objects x SET tenant_id=o.id FROM organizations o
WHERE x.tenant_id IS NULL AND trim(COALESCE(x.organization,''))<>'' AND lower(trim(x.organization))=lower(trim(o.name));
UPDATE salary_records s SET tenant_id=o.id FROM organizations o
WHERE s.tenant_id IS NULL AND trim(COALESCE(s.organization,''))<>'' AND lower(trim(s.organization))=lower(trim(o.name));
UPDATE employee_balances b SET tenant_id=e.tenant_id FROM employees e
WHERE b.tenant_id IS NULL AND b.employee_id=e.id AND e.tenant_id IS NOT NULL;
UPDATE bank_statement_payments b SET tenant_id=e.tenant_id FROM employees e
WHERE b.tenant_id IS NULL AND b.employee_id=e.id AND e.tenant_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS app_sessions (
  sid TEXT PRIMARY KEY,
  sess JSONB NOT NULL,
  expire TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_app_sessions_expire ON app_sessions(expire);


-- Append-only защита юридически значимого audit trail.
CREATE OR REPLACE FUNCTION protect_audit_events() RETURNS trigger AS $$
BEGIN
  IF current_setting('app.allow_audit_mutation', TRUE)='on' THEN
    RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
  END IF;
  RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_events_no_update ON audit_events;
CREATE TRIGGER trg_audit_events_no_update BEFORE UPDATE ON audit_events
FOR EACH ROW EXECUTE FUNCTION protect_audit_events();

DROP TRIGGER IF EXISTS trg_audit_events_no_delete ON audit_events;
CREATE TRIGGER trg_audit_events_no_delete BEFORE DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION protect_audit_events();
