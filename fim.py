import datetime
import hashlib
import os
import time
import requests

# إعدادات المجلد المستهدف والتليجرام
MONITOR_DIR = "."
BASELINE_FILE = "folder_baseline.txt"
LOG_FILE = "security_log.txt"
CHECK_INTERVAL = 5

# البيانات الخاصة بك جاهزة ومربوطة بنجاح
TELEGRAM_BOT_TOKEN = "9113538590:AAH4BCTRJeeF9UWbWPxVaRP_GMdqnxg-7-A"
TELEGRAM_CHAT_ID = "8321955546"


def send_telegram_alert(message):
  """إرسال إشعار فوري على تليجرام"""
  url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
  payload = {
      "chat_id": TELEGRAM_CHAT_ID,
      "text": f"🚨 تنبيه أمني من أداة FIM:\n{message}",
  }
  try:
    requests.post(url, data=payload)
  except Exception as e:
    print(f"فشل إرسال إشعار تليجرام: {e}")


def calculate_file_hash(file_path):
  sha256_hash = hashlib.sha256()
  try:
    with open(file_path, "rb") as f:
      for byte_block in iter(lambda: f.read(4096), b""):
        sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
  except Exception:
    return None


def log_event(message):
  current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  log_entry = f"[{current_time}] {message}\n"
  with open(LOG_FILE, "a", encoding="utf-8") as log:
    log.write(log_entry)
  print(log_entry.strip())

  if "تحذير" in message or "حذف" in message or "إضافة" in message:
    send_telegram_alert(message)


def scan_directory():
  file_hashes = {}
  for root, dirs, files in os.walk(MONITOR_DIR):
    for file in files:
      if file in [BASELINE_FILE, LOG_FILE, "fim.py"]:
        continue
      file_path = os.path.join(root, file)
      file_hash = calculate_file_hash(file_path)
      if file_hash:
        file_hashes[file_path] = file_hash
  return file_hashes


def load_baseline():
  baseline = {}
  if os.path.exists(BASELINE_FILE):
    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
      for line in f:
        if ":" in line:
          path, hsh = line.strip().split(":", 1)
          baseline[path] = hsh
  return baseline


def save_baseline(baseline):
  with open(BASELINE_FILE, "w", encoding="utf-8") as f:
    for path, hsh in baseline.items():
      f.write(f"{path}:{hsh}\n")


def main():
  log_event("=== بدء تشغيل نظام مراقبة سلامة الملفات (FIM) المتطور ===")

  if not os.path.exists(BASELINE_FILE):
    initial_baseline = scan_directory()
    save_baseline(initial_baseline)
    log_event(
        f"تم إنشاء البصمة الأساسية للمجلد بنجاح (مراقبة {len(initial_baseline)}"
        " ملف)."
    )

  log_event(
      f"جاري مراقبة التغييرات كل {CHECK_INTERVAL} ثوانٍ... (اضغط Ctrl+C للإيقاف)"
  )

  try:
    while True:
      baseline = load_baseline()
      current_state = scan_directory()

      for path, saved_hash in baseline.items():
        if path not in current_state:
          log_event(f"🚨 تحذير خطير: تم حذف الملف! -> {path}")
        elif current_state[path] != saved_hash:
          log_event(f"⚠️ تنبيه أمني: تم التلاعب وتغيير محتوى الملف! -> {path}")

      for path in current_state:
        if path not in baseline:
          log_event(f"📁 ملاحظة: تم إضافة ملف جديد للمجلد! -> {path}")
          baseline[path] = current_state[path]
          save_baseline(baseline)

      time.sleep(CHECK_INTERVAL)

  except KeyboardInterrupt:
    log_event("=== تم إيقاف نظام المراقبة بواسطة المستخدم ===")


if __name__ == "__main__":
  main()