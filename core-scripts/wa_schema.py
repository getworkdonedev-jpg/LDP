import sqlite3, shutil, tempfile, os

wa_dir = os.path.expanduser("~/Library/Group Containers/group.net.whatsapp.whatsapp.shared")
contacts_db = os.path.join(wa_dir, "ContactsV2.sqlite")

tmp_contacts = tempfile.mktemp(suffix=".db")
shutil.copy2(contacts_db, tmp_contacts)
conn = sqlite3.connect(tmp_contacts)
cur = conn.cursor()

print("--- ZWAADDRESSBOOKCONTACT ---")
try:
    columns = [col[1] for col in cur.execute("PRAGMA table_info(ZWAADDRESSBOOKCONTACT)")]
    print("Cols:", [c for c in columns if "NAME" in c.upper() or "PHONE" in c.upper() or "JID" in c.upper()])
    print("Sample:", cur.execute("SELECT * FROM ZWAADDRESSBOOKCONTACT WHERE ZFIRSTNAME IS NOT NULL LIMIT 1").fetchone()[:10]) # just first 10 for safety
except Exception as e: print(e)

print("--- ZWAXMPPCONTACT ---")
try:
    columns = [col[1] for col in cur.execute("PRAGMA table_info(ZWAXMPPCONTACT)")]
    print("Cols:", [c for c in columns if "NAME" in c.upper() or "PHONE" in c.upper() or "JID" in c.upper()])
    row = cur.execute("SELECT * FROM ZWAXMPPCONTACT WHERE ZDATANULLABLEPHONENUMBER IS NOT NULL LIMIT 1").fetchone()
    if row: print("Sample:", row[:10])
except Exception as e: print(e)

conn.close()
os.unlink(tmp_contacts)
