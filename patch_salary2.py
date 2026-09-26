import re, os

base = os.path.dirname(os.path.abspath(__file__))
html_path = os.path.join(base, 'public', 'index.html')
srv_path = os.path.join(base, 'server.js')

with open(html_path, 'r', encoding='utf-8') as f:
    html = f.read()
with open(srv_path, 'r', encoding='utf-8') as f:
    srv = f.read()

ok = []
fail = []

def patch(label, pattern, repl, text, flags=0):
    new = re.sub(pattern, repl, text, flags=flags)
    if new != text:
        ok.append(label)
        return new
    else:
        fail.append(label)
        return text

# === index.html fixes ===

# 1. Date field in input form
html = patch('Date field input form',
    r'<input type="text" id="inpYear" value="2026">',
    '<input type="text" id="inpYear" value="2026"></div>\n'
    '          <div class="form-group"><label>\u0414\u0430\u0442\u0430 \u043d\u0430\u0447\u0438\u0441\u043b\u0435\u043d\u0438\u044f</label><input type="date" id="inpChargeDate">',
    html)

# 2. Export all button text
html = patch('Export all button',
    r'<button class="btn btn-blue btn-sm" onclick="exportSalaryCSV\(\)">\u042d\u043a\u0441\u043f\u043e\u0440\u0442 CSV</button>',
    '<button class="btn btn-blue btn-sm" onclick="exportSalaryCSV()">\u042d\u043a\u0441\u043f\u043e\u0440\u0442 \u0432 Excel (\u0432\u0441\u0435)</button>',
    html)

# === server.js fixes ===

# 3. Add charge_date to POST destructuring
srv = patch('POST destructure charge_date',
    r"const \{ employee_fio, object_name, month, year, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid \} = req\.body;\n  try \{\n    const result = await pool\.query\(\n      `INSERT INTO",
    "const { employee_fio, object_name, month, year, charge_date, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid } = req.body;\n  try {\n    const result = await pool.query(\n      `INSERT INTO",
    srv)

# 4. Fix INSERT VALUES: $12 -> $13
srv = patch('INSERT VALUES fix $13',
    r"VALUES \(\$1,\$2,\$3,\$4,\$5,\$6,\$7,\$8,\$9,\$10,\$11,\$12\) RETURNING \*",
    "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *",
    srv)

# 5. Add charge_date to PUT destructuring
srv = patch('PUT destructure charge_date',
    r"const \{ employee_fio, object_name, month, year, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid \} = req\.body;\n  try \{\n    const result = await pool\.query\(\n      `UPDATE",
    "const { employee_fio, object_name, month, year, charge_date, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid } = req.body;\n  try {\n    const result = await pool.query(\n      `UPDATE",
    srv)

# 6. Fix UPDATE SET clause: charge_date=$5, hour_rate=$6, hours=$7
srv = patch('UPDATE SET order fix',
    r"employee_fio=\$1, object_name=\$2, month=\$3, year=\$4, hour_rate=\$5, hours=\$6,\s+charge_date=\$7",
    "employee_fio=$1, object_name=$2, month=$3, year=$4, charge_date=$5, hour_rate=$6, hours=$7,",
    srv)

# 7. ALTER TABLE before CREATE TABLE
srv = patch('ALTER TABLE charge_date',
    r"(CREATE TABLE IF NOT EXISTS salary_records)",
    "ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS charge_date DATE;\n  \\1",
    srv)

# Write files
with open(html_path, 'w', encoding='utf-8') as f:
    f.write(html)
with open(srv_path, 'w', encoding='utf-8') as f:
    f.write(srv)

print('=== Результат патча 2 ===')
print('OK:')
for x in ok:
    print('  + ' + x)
if fail:
    print('НЕ НАЙДЕНО:')
    for x in fail:
        print('  - ' + x)
print(f'\nВсего: {len(ok)} применено, {len(fail)} пропущено')
