import hashlib
import os
import sqlite3
import streamlit as st

# إعدادات الصفحة
st.set_page_config(
    page_title="FIM Security Dashboard", page_icon="🛡️", layout="wide"
)

# تصميم وتنسيق CSS مخصص لواجهة سيبرانية احترافية
st.markdown(
    """
    <style>
    .main {
        background-color: #0e1117;
    }
    .stButton>button {
        width: 100%;
        border-radius: 8px;
        font-weight: bold;
        height: 3em;
        transition: 0.3s;
    }
    .stButton>button:hover {
        border-color: #00ffcc;
        color: #00ffcc;
    }
    .metric-card {
        background-color: #161b22;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #30363d;
        text-align: center;
    }
    h1, h2, h3 {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    </style>
""",
    unsafe_allow_html=True,
)

st.markdown(
    "<h1 style='text-align: center; color: #58a6ff;'>🛡️ Enterprise File Integrity Monitoring (FIM)</h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "<p style='text-align: center; color: #8b949e;'>نظام أمني متكامل لمراقبة سلامة الملفات وكشف التغييرات والتهديدات لحظياً</p>",
    unsafe_allow_html=True,
)
st.markdown("---")

DB_FILE = "fim_security.db"
MONITOR_DIR = "."


# إعداد قاعدة البيانات والجداول
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS baseline (
            path TEXT PRIMARY KEY,
            hash TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT,
            file_path TEXT
        )
    """)
    conn.commit()
    conn.close()


# حساب بصمة الملف (SHA-256)
def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None


# استثناء ملفات النظام وقاعدة البيانات
def is_ignored(file_name, root_path):
    if (
        ".git" in root_path
        or DB_FILE in root_path
        or file_name.endswith((".db", "-journal", "-wal", "-shm"))
    ):
        return True
    return False


# حفظ النسخة الأساسية
def reset_baseline():
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM baseline")

    count = 0
    for root, dirs, files in os.walk(MONITOR_DIR):
        for file in files:
            if is_ignored(file, root):
                continue
            full_path = os.path.join(root, file)
            file_hash = calculate_file_hash(full_path)
            if file_hash:
                cursor.execute(
                    "INSERT OR REPLACE INTO baseline (path, hash) VALUES (?, ?)",
                    (full_path, file_hash),
                )
                count += 1

    conn.commit()
    conn.close()
    return count


# فحص التغييرات
def scan_files():
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT path, hash FROM baseline")
    baseline_data = {row[0]: row[1] for row in cursor.fetchall()}

    if not baseline_data:
        conn.close()
        return (
            None,
            "⚠️ الرجاء إنشاء النسخة الأساسية (Baseline) أولاً من لوحة التحكم.",
        )

    current_files = {}
    for root, dirs, files in os.walk(MONITOR_DIR):
        for file in files:
            if is_ignored(file, root):
                continue
            full_path = os.path.join(root, file)
            file_hash = calculate_file_hash(full_path)
            if file_hash:
                current_files[full_path] = file_hash

    modified = []
    added = []
    deleted = []

    for path, old_hash in baseline_data.items():
        if path not in current_files:
            deleted.append(path)
            cursor.execute(
                "INSERT INTO logs (event_type, file_path) VALUES (?, ?)",
                ("DELETED", path),
            )
        elif current_files[path] != old_hash:
            modified.append(path)
            cursor.execute(
                "INSERT INTO logs (event_type, file_path) VALUES (?, ?)",
                ("MODIFIED", path),
            )

    for path in current_files:
        if path not in baseline_data:
            added.append(path)
            cursor.execute(
                "INSERT INTO logs (event_type, file_path) VALUES (?, ?)",
                ("ADDED", path),
            )

    conn.commit()
    conn.close()
    return modified, added, deleted


# القائمة الجانبية
st.sidebar.image(
    "https://img.icons8.com/color/96/cyber-security.png", width=80
)
st.sidebar.title("لوحة التحكم")
menu = st.sidebar.selectbox(
    "اختر القسم الرئيسي",
    ["🔍 المراقبة والفحص الأمني", "📋 سجل الأحداث والعمليات (Logs)"],
)

if menu == "🔍 المراقبة والفحص الأمني":
    st.subheader("⚙️ إعدادات وإدارة الملفات")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 إنشاء / تحديث النسخة الأساسية (Baseline)"):
            with st.spinner("جاري أخذ بصمات الملفات وفهرستها..."):
                count = reset_baseline()
                st.success(
                    f"✅ تم إنشاء النسخة الأساسية بنجاح! تم رصد {count} ملف."
                )

    with col2:
        if st.button("🚀 بدء الفحص الأمني الشامل (Scan)"):
            with st.spinner("جاري فحص الملفات ومقارنتها..."):
                result = scan_files()
                if isinstance(result, tuple):
                    modified, added, deleted = (
                        result[0],
                        result[1],
                        result[2],
                    )

                    st.markdown("---")
                    st.subheader("📊 تقرير نتائج الفحص:")

                    m_col, a_col, d_col = st.columns(3)

                    with m_col:
                        st.metric(
                            label="⚠️ الملفات المعدلة", value=len(modified)
                        )
                        if modified:
                            for m in modified:
                                st.warning(f"معدل: {m}")

                    with a_col:
                        st.metric(
                            label="➕ الملفات المضافة حديثاً", value=len(added)
                        )
                        if added:
                            for a in added:
                                st.info(f"مضاف: {a}")

                    with d_col:
                        st.metric(label="❌ الملفات المحذوفة", value=len(deleted))
                        if deleted:
                            for d in deleted:
                                st.error(f"محذوف: {d}")

                    if not modified and not added and not deleted:
                        st.balloons()
                        st.success(
                            "🎉 النظام في أمان تام! لم يتم رصد أي تغيرات غير مرغوب فيها."
                        )
                else:
                    st.warning(result)

elif menu == "📋 سجل الأحداث والعمليات (Logs)":
    st.subheader("📜 سجل التهديدات والأحداث التاريخية")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, event_type, file_path FROM logs ORDER BY id DESC"
    )
    logs = cursor.fetchall()
    conn.close()

    if logs:
        st.dataframe(
            [
                {
                    "الوقت والتاريخ": row[0],
                    "نوع الحدث": row[1],
                    "مسار الملف": row[2],
                }
                for row in logs
            ],
            use_container_width=True,
        )
    else:
        st.info("ℹ️ لا توجد سجلات مسجلة حتى الآن.")