import hashlib
import json
import os
import sqlite3
import threading
import time
import streamlit as st

# إعدادات الصفحة
st.set_page_config(
    page_title="FIM Security Dashboard", page_icon="🛡️", layout="wide"
)

# تنسيق CSS مخصص لواجهة سيبرانية متقدمة
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
    "<p style='text-align: center; color: #8b949e;'>نظام أمني متكامل لمراقبة سلامة الملفات وكشف التغييرات والتهديدات لحظياً مع أدوات التحليل المتقدمة</p>",
    unsafe_allow_html=True,
)
st.markdown("---")

DB_FILE = "fim_security.db"


# إعداد قاعدة البيانات
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


# استثناء ملفات النظام والداتابيز
def is_ignored(file_name, root_path):
    if (
        ".git" in root_path
        or DB_FILE in root_path
        or file_name.endswith((".db", "-journal", "-wal", "-shm"))
    ):
        return True
    return False


# حفظ النسخة الأساسية
def reset_baseline(target_dir):
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM baseline")

    count = 0
    for root, dirs, files in os.walk(target_dir):
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


# فحص التغييرات وتسجيل اللوجات
def scan_files(target_dir):
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT path, hash FROM baseline")
    baseline_data = {row[0]: row[1] for row in cursor.fetchall()}

    if not baseline_data:
        conn.close()
        return None, "⚠️ الرجاء إنشاء النسخة الأساسية (Baseline) أولاً."

    current_files = {}
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            if is_ignored(file, root):
                continue
            full_path = os.path.join(root, file)
            file_hash = calculate_file_hash(full_path)
            if file_hash:
                current_files[full_path] = file_hash

    modified, added, deleted = [], [], []

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


# تصفير اللوجات
def clear_all_logs():
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM logs")
    conn.commit()
    conn.close()


# القائمة الجانبية
st.sidebar.image(
    "https://img.icons8.com/color/96/cyber-security.png", width=80
)
st.sidebar.title("لوحة التحكم السيبرانية")
menu = st.sidebar.selectbox(
    "اختر القسم الرئيسي",
    [
        "🔍 المراقبة والفحص الأمني",
        "📋 سجل الأحداث والعمليات (Logs)",
        "📊 التقارير والتصدير (Reports)",
    ],
)

if menu == "🔍 المراقبة والفحص الأمني":
    st.subheader("⚙️ إعدادات وفحص المسارات")

    target_dir = st.text_input(
        "📂 حدد مسار المجلد المراد مراقبته (اتركه نقطة للمسار الحالي):", value="."
    )

    if not os.path.exists(target_dir):
        st.error("❌ المسار المدخل غير موجود.")
    else:
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔄 إنشاء / تحديث النسخة الأساسية (Baseline)"):
                with st.spinner("جاري أخذ بصمات الملفات وفهرستها..."):
                    count = reset_baseline(target_dir)
                    st.success(f"✅ تم إنشاء النسخة الأساسية! رصد {count} ملف.")

        with col2:
            if st.button("🚀 بدء الفحص الأمني الشامل (Scan)"):
                with st.spinner("جاري الفحص والمقارنة..."):
                    result = scan_files(target_dir)
                    if isinstance(result, tuple):
                        modified, added, deleted = (
                            result[0],
                            result[1],
                            result[2],
                        )

                        st.markdown("---")
                        st.subheader("📊 نتائج فحص النزاهة:")
                        m_col, a_col, d_col = st.columns(3)

                        with m_col:
                            st.metric(
                                label="⚠️ الملفات المعدلة", value=len(modified)
                            )
                            for m in modified:
                                st.warning(f"معدل: {m}")
                        with a_col:
                            st.metric(
                                label="➕ الملفات المضافة", value=len(added)
                            )
                            for a in added:
                                st.info(f"مضاف: {a}")
                        with d_col:
                            st.metric(
                                label="❌ الملفات المحذوفة", value=len(deleted)
                            )
                            for d in deleted:
                                st.error(f"محذوف: {d}")

                        if not modified and not added and not deleted:
                            st.balloons()
                            st.success(
                                "🎉 النظام سليم تماماً ولم يُرصد أي تغيير خبيث."
                            )
                    else:
                        st.warning(result)

        # قسم المراقبة التلقائية الحية (Real-time Watcher Simulator)
        st.markdown("---")
        st.subheader("⚡ المراقبة الحية التلقائية (Background Watcher)")
        auto_scan = st.toggle("تفعيل الفحص التلقائي كل (5 ثوانٍ)")

        if auto_scan:
            placeholder = st.empty()
            for _ in range(30):  # محاكاة دورات المراقبة
                m, a, d = scan_files(target_dir)
                with placeholder.container():
                    if m or a or d:
                        st.error(
                            f"🚨 تنبيه أمني فوري: تم رصد تغييرات! (معدل: {len(m)} | مضاف: {len(a)} | محذوف: {len(d)})"
                        )
                    else:
                        st.info(
                            "🟢 نظام المراقبة الحية يعمل... الحالة مستقرة وآمنة."
                        )
                time.sleep(5)

elif menu == "📋 سجل الأحداث والعمليات (Logs)":
    st.subheader("📜 سجل التهديدات والأحداث التاريخية")

    filter_col1, filter_col2 = st.columns([2, 1])
    with filter_col1:
        event_filter = st.selectbox(
            "🔍 تصفية حسب نوع الحدث:",
            ["الكل (All)", "MODIFIED", "ADDED", "DELETED"],
        )
    with filter_col2:
        st.write("")
        st.write("")
        if st.button("🗑️ مسح جميع السجلات"):
            clear_all_logs()
            rerun = getattr(st, "rerun", getattr(st, "experimental_rerun", None))
            if rerun:
                rerun()

    init_db()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    if event_filter == "الكل (All)":
        cursor.execute(
            "SELECT timestamp, event_type, file_path FROM logs ORDER BY id DESC"
        )
    else:
        cursor.execute(
            "SELECT timestamp, event_type, file_path FROM logs WHERE event_type = ? ORDER BY id DESC",
            (event_filter,),
        )

    logs = cursor.fetchall()
    conn.close()

    if logs:
        for row in logs:
            st.code(
                f"[{row[0]}] | الحدث: {row[1]} | المسار: {row[2]}", language="text"
            )
    else:
        st.info("ℹ️ لا توجد سجلات مطابقة حالياً.")

elif menu == "📊 التقارير والتصدير (Reports)":
    st.subheader("📥 تصدير تقارير التحقيق الجنائي الرقمي")
    st.write(
        "يمكنك تصدير كافة سجلات التهديدات والأحداث الأمنية للاحتفاظ بها أو إرفاقها في تقارير مشروع التخرج."
    )

    init_db()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, event_type, file_path FROM logs ORDER BY id DESC"
    )
    logs_data = cursor.fetchall()
    conn.close()

    if logs_data:
        # تجهيز البيانات للتصدير
        report_list = [
            {"Timestamp": r[0], "Event": r[1], "Path": r[2]} for r in logs_data
        ]
        json_data = json.dumps(report_list, indent=4, ensure_ascii=False)

        col_exp1, col_exp2 = st.columns(2)
        with col_exp1:
            st.download_button(
                label="📥 تحميل التقرير بصيغة JSON",
                data=json_data,
                file_name="fim_security_report.json",
                mime="application/json",
            )
        with col_exp2:
            csv_text = "Timestamp,Event,Path\n" + "\n".join(
                [f"{r[0]},{r[1]},{r[2]}" for r in report_list]
            )
            st.download_button(
                label="📥 تحميل التقرير بصيغة CSV",
                data=csv_text,
                file_name="fim_security_report.csv",
                mime="text/csv",
            )
    else:
        st.info("ℹ️ لا توجد سجلات كافية لتصدير تقرير حتى الآن.")