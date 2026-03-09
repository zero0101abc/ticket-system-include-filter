with open("backend/db.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

new_lines = []
skip = False
for line in lines:
    if "def sync_tickets_to_json():" in line:
        pass
    if "with shop name update (cdcik -> ik)" in line:
        line = line.replace("with shop name update (cdcik -> ik)", "from SQLite")
    if "cdcIK" in line and "replace" in line:
        continue
    if "cdcIK" in line and "ticket.get('shop')" in line:
        continue
    new_lines.append(line)

with open("backend/db.py", "w", encoding="utf-8") as f:
    f.writelines(new_lines)
