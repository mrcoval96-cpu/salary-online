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
    global ok, fail
    new = re.sub(pattern, lambda m: repl, text, flags=flags)
    if new != text:
        ok.append(label)
        return new
    else:
        fail.append(label)
        return text

# 1. Mobile header CSS
pat = r'header\{background:#0f3460;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center\}'
repl = 'header{background:#0f3460;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}'
repl += '\n@media(max-width:768px){header{flex-direction:column;text-align:center;padding:10px 12px}'
repl += 'header h1{font-size:16px}header .user-info{flex-direction:column;gap:6px;font-size:13px}'
repl += '.tabs{overflow-x:auto;flex-wrap:nowrap;padding:0 8px;-webkit-overflow-scrolling:touch}'
repl += '.tab-btn{padding:10px 12px;font-size:13px;white-space:nowrap}'
repl += '.modal{max-width:95vw;max-height:90vh;overflow-y:auto}}'
html = patch('Mobile header CSS', pat, repl, html)

# 2. Salary card styles
pat = r'\.salary-detail\{display:none;margin-top:12px;border-top:1px solid #eee;padding-top:12px\}'
repl = '.salary-card{cursor:pointer;transition:box-shadow .2s}\n'
repl += '.salary-card:hover{box-shadow:0 2px 8px rgba(0,0,0,0.12)}\n'
repl += '.salary-detail{display:none;margin-top:12px;border-top:1px solid #eee;padding-top:12px}\n'
repl += '.salary-detail.show{display:block}'
html = patch('Salary card CSS', pat, repl, html)

# 3. Date field in input form
pat = '<div class="form-group"><label>Год</label><input type="text" id="inpYear"></div>'
repl = '<div class="form-group"><label>Год</label><input type="text" id="inpYear"></div>'
repl += '<div class="form-group"><label>Дата начисления</label><input type="date" id="inpChargeDate"></div>'
html = patch('Date field input', pat, repl, html)

# 4. Date field in edit modal
pat = '<div class="form-group"><label>Год</label><input type="text" id="editYear"></div>'
repl = '<div class="form-group"><label>Год</label><input type="text" id="editYear"></div>'
repl += '<div class="form-group"><label>Дата начисления</label><input type="date" id="editChargeDate"></div>'
html = patch('Date field edit modal', pat, repl, html)

# 5. Extra charges readable display
pat = r"<td>' \+ \(r\.extra_charges\|\|'\[\]'\) \+ '</td>"
repl = "<td>' + formatExtra(r.extra_charges) + '</td>"
html = patch('Extra charges display', pat, repl, html)

# 6. formatExtra function
pat = r'function renderSalary\(\) \{'
repl = "function formatExtra(ec){try{var a=typeof ec==='string'?JSON.parse(ec||'[]'):(ec||[]);"
repl += "if(!a.length)return '&mdash;';return a.map(function(e){return '<b>'+(e.description||e.name||'?')+'</b>: '+(e.amount||0)+' \\u20bd';}).join('<br>');}"
repl += "catch(e){return '&mdash;';}}\n"
repl += 'function renderSalary() {'
html = patch('formatExtra function', pat, repl, html)

# 7. Date column header
pat = '<th>Объект</th><th>Месяц</th><th>Год</th>'
repl = '<th>Дата</th><th>Объект</th><th>Месяц</th><th>Год</th>'
html = patch('Date column header', pat, repl, html)

# 8. Date column body
pat = r"recs\.map\(r => '<tr><td>' \+ \(r\.object_name\|\|''\) \+ '</td><td>' \+ \(r\.month\|\|''\) \+ '</td>"
repl = "recs.map(r => '<tr><td>' + (r.charge_date||'&mdash;') + '</td><td>' + (r.object_name||'') + '</td><td>' + (r.month||'') + '</td>"
html = patch('Date column body', pat, repl, html)

# 9. Export to Excel - replace exportSalaryCSV
pat = r'function exportSalaryCSV\(\) \{.*?\}'
repl = (
    "function exportSalaryCSV(fio) {\n"
    "  var recs = fio ? salaryRecords.filter(function(r){return r.employee_fio===fio;}) : salaryRecords.slice();\n"
    "  if(!recs.length){toast('Нет данных','error');return;}\n"
    "  var wb = XLSX.utils.book_new();\n"
    "  var rows = recs.map(function(r){\n"
    "    var ec=r.extra_charges;\n"
    "    if(typeof ec==='string')try{ec=JSON.parse(ec||'[]')}catch(e){ec=[]}\n"
    "    ec=ec||[];\n"
    "    var ecStr=ec.map(function(e){return (e.description||'')+': '+(e.amount||0)}).join('; ');\n"
    "    return {ФИО:r.employee_fio,Дата:r.charge_date||'',Объект:r.object_name||'',Месяц:r.month||'',Год:r.year||'',\n"
    "    'Ставка':r.hour_rate||0,Часы:r.hours||0,'Сут.дни':r.per_diem_days||0,'Сут.ставка':r.per_diem_rate||0,\n"
    "    'Доп.начисления':ecStr,Итого:r.total||0,Выплачено:r.paid||0,Долг:((r.total||0)-(r.paid||0))};\n"
    "  });\n"
    "  var ws1 = XLSX.utils.json_to_sheet(rows);\n"
    "  XLSX.utils.book_append_sheet(wb, ws1, 'Записи');\n"
    "  var months={};\n"
    "  recs.forEach(function(r){\n"
    "    var key=(r.month||'')+' '+(r.year||'');\n"
    "    if(!months[key])months[key]={Месяц:key,Начислено:0,Выплачено:0,Долг:0};\n"
    "    months[key].Начислено+=parseFloat(r.total||0);\n"
    "    months[key].Выплачено+=parseFloat(r.paid||0);\n"
    "    months[key].Долг+=parseFloat(r.total||0)-parseFloat(r.paid||0);\n"
    "  });\n"
    "  var ws2 = XLSX.utils.json_to_sheet(Object.values(months));\n"
    "  XLSX.utils.book_append_sheet(wb, ws2, 'По месяцам');\n"
    "  var t=recs.reduce(function(s,r){return s+parseFloat(r.total||0)},0);\n"
    "  var p=recs.reduce(function(s,r){return s+parseFloat(r.paid||0)},0);\n"
    "  var ws3 = XLSX.utils.json_to_sheet([{Показатель:'Начислено',Значение:t},{Показатель:'Выплачено',Значение:p},{Показатель:'Задолженность',Значение:t-p}]);\n"
    "  XLSX.utils.book_append_sheet(wb, ws3, 'Итоги');\n"
    "  var fn = fio ? fio.replace(/\\s+/g,'_')+'.xlsx' : 'salary_all.xlsx';\n"
    "  XLSX.writeFile(wb, fn);\n"
    "}"
)
html = re.sub(pat, lambda m: repl, html, flags=re.DOTALL)
if 'XLSX.writeFile' in html:
    ok.append('Excel export')
else:
    fail.append('Excel export')

# 10. Per-person export button - simple string replacement
old_btn = "+ Добавить запись</button>';"
new_btn = """+ Добавить запись</button> <button class="btn btn-blue btn-sm" onclick="exportSalaryCSV(\\'' + fio.replace(/'/g, "\\'") + '\\')">Экспорт</button>';"""

if old_btn in html:
    html = html.replace(old_btn, new_btn, 1)
    ok.append('Per-person export button')
else:
    fail.append('Per-person export button')

# 11. Responsible field hint
pat = '<label>Ответственный сотрудник</label><input type="text" id="objResp">'
repl = '<label>Ответственный сотрудник (через запятую)</label><input type="text" id="objResp" placeholder="Иванов И.И., Петров П.П.">'
html = patch('Responsible hint', pat, repl, html)

# 12. charge_date in calculateAndSave POST
pat = r"year: document\.getElementById\('inpYear'\)\.value,"
repl = "year: document.getElementById('inpYear').value,\n      charge_date: document.getElementById('inpChargeDate').value || null,"
html = patch('charge_date in POST', pat, repl, html)

# 13. charge_date in edit load
pat = r"document\.getElementById\('editYear'\)\.value = r\.year \|\| '';"
repl = "document.getElementById('editYear').value = r.year || '';\n  document.getElementById('editChargeDate').value = r.charge_date || '';"
html = patch('charge_date in edit load', pat, repl, html)

# 14. charge_date in edit save
pat = r"year: document\.getElementById\('editYear'\)\.value,"
repl = "year: document.getElementById('editYear').value,\n      charge_date: document.getElementById('editChargeDate').value || null,"
html = patch('charge_date in edit save', pat, repl, html)

# 15. Export all button text
pat = r'<button class="btn btn-green btn-sm" onclick="exportSalaryCSV\(\)">Экспорт CSV</button>'
repl = '<button class="btn btn-green btn-sm" onclick="exportSalaryCSV()">Экспорт в Excel (всё)</button>'
html = patch('Export all button text', pat, repl, html)

# === server.js ===

# 16. ALTER TABLE charge_date
pat = r"CREATE TABLE IF NOT EXISTS salary_records \("
repl = "ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS charge_date DATE;\n  CREATE TABLE IF NOT EXISTS salary_records ("
srv = patch('ALTER TABLE charge_date', pat, repl, srv)

# 17. charge_date INSERT columns
pat = r"INSERT INTO salary_records \(employee_fio, object_name, month, year, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid\)"
repl = "INSERT INTO salary_records (employee_fio, object_name, month, year, charge_date, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid)"
srv = patch('charge_date INSERT columns', pat, repl, srv)

# 18. charge_date INSERT values
pat = r"\[employee_fio\|\|'', object_name\|\|'', month\|\|'', year\|\|'', hour_rate\|\|0, hours\|\|0, per_diem_days\|\|0, per_diem_rate\|\|0,"
repl = "[employee_fio||'', object_name||'', month||'', year||'', charge_date||null, hour_rate||0, hours||0, per_diem_days||0, per_diem_rate||0,"
srv = patch('charge_date INSERT values', pat, repl, srv)

# 19. charge_date UPDATE SET
pat = r"per_diem_days=\$7, per_diem_rate=\$8, extra_charges=\$9, payments=\$10, total=\$11, paid=\$12 WHERE id=\$13"
repl = "charge_date=$7, per_diem_days=$8, per_diem_rate=$9, extra_charges=$10, payments=$11, total=$12, paid=$13 WHERE id=$14"
srv = patch('charge_date UPDATE SET', pat, repl, srv)

# 20. charge_date UPDATE values
pat = r"\[employee_fio\|\|'', object_name\|\|'', month\|\|'', year\|\|'', per_diem_days\|\|0, per_diem_rate\|\|0,"
repl = "[employee_fio||'', object_name||'', month||'', year||'', charge_date||null, per_diem_days||0, per_diem_rate||0,"
srv = patch('charge_date UPDATE values', pat, repl, srv)

# 21. charge_date bulk import values
pat = r"rec\.per_diem_days\|\|0, rec\.per_diem_rate\|\|0, rec\.extra_charges\|\|'\[\]', rec\.payments\|\|'\[\]', rec\.total\|\|0, rec\.paid\|\|0"
repl = "rec.per_diem_days||0, rec.per_diem_rate||0, rec.extra_charges||'[]', rec.payments||'[]', rec.total||0, rec.paid||0, rec.charge_date||null"
srv = patch('charge_date bulk import', pat, repl, srv)

# Write files
with open(html_path, 'w', encoding='utf-8') as f:
    f.write(html)
with open(srv_path, 'w', encoding='utf-8') as f:
    f.write(srv)

print('\n=== Результат патча ===')
print('OK:')
for x in ok:
    print('  + ' + x)
if fail:
    print('НЕ НАЙДЕНО:')
    for x in fail:
        print('  - ' + x)
print(f'\nВсего: {len(ok)} применено, {len(fail)} пропущено')
