# DETECTION TROUBLESHOOTING GUIDE

## 🔍 دليل استكشاف أخطاء الكشف

### الخطوة 1️⃣: تشغيل الفحص التشخيصي

```bash
cd c:\Users\(-_\Pictures\RansomwareDefenseKit
python diagnostic_check.py
```

سيتحقق من:
- ✅ إصدار Python
- ✅ المكتبات المطلوبة
- ✅ هيكل المشروع
- ✅ ملف الإعدادات
- ✅ مجلد السجلات
- ✅ وظائف watchdog
- ✅ مجلد الاختبار

---

### الخطوة 2️⃣: اختبار watchdog بشكل منفصل

```bash
# Terminal 1: ابدأ مراقبة الاختبار
python test_monitoring_debug.py

# Terminal 2: شغّل محاكي السلوك
cd c:\Users\(-_\Pictures\RansomwareDefenseKit2
python test_ransomware_behavior.py
```

**ماذا يجب أن تراه:**
```
✓ CREATED: C:\Test_Quarantine\document_0.txt
🔄 RENAMED: C:\Test_Quarantine\document_0.txt → C:\Test_Quarantine\document_0.txt.locked
   🚨 SUSPICIOUS EXTENSION DETECTED!
```

---

### الخطوة 3️⃣: تثبيت المكتبات المفقودة

إذا كانت `watchdog` مفقودة:

```bash
pip install watchdog
```

إذا كانت `psutil` مفقودة:

```bash
pip install psutil
```

تثبيت كل المتطلبات:

```bash
pip install -r requirements.txt
```

---

### الخطوة 4️⃣: التحقق من الصلاحيات

**تشغيل كمسؤول (Administrator):**

1. أغلق البرنامج
2. انقر بزر الماوس الأيمن على `main.py`
3. اختر **"Run as Administrator"**

أو استخدم PowerShell:

```powershell
Start-Process python -ArgumentList "main.py" -Verb RunAs
```

---

### الخطوة 5️⃣: فحص السجلات

بعد تشغيل البرنامج، افحص:

```bash
# عرض السجلات
type logs\events.jsonl
type logs\summary.csv
```

إذا كانت فارغة:
- ❌ الكشف لا يعمل
- ✅ شغّل `diagnostic_check.py` للتحقق

---

### الخطوة 6️⃣: المشاكل الشائعة والحلول

| المشكلة | السبب | الحل |
|---------|-------|------|
| لا توجد أحداث | watchdog غير مثبت | `pip install watchdog` |
| الكشف لا يعمل | المجلد غير مراقب | أضف المجلد في Settings |
| خطأ صلاحيات | ليس مسؤول | Run as Administrator |
| UI لا يتحدث | Signals غير متصلة | تحقق من الكود |
| السجلات فارغة | Observer لم يبدأ | تحقق من start_monitoring() |

---

### الخطوة 7️⃣: اختبار سريع

قم بإنشاء هذا الملف للاختبار السريع:

**quick_test.py:**
```python
import os
import time

# إنشاء مجلد اختبار
test_dir = r"C:\Quick_Test"
os.makedirs(test_dir, exist_ok=True)

# إنشاء ملف عادي
normal_file = os.path.join(test_dir, "test.txt")
with open(normal_file, "w") as f:
    f.write("Test content")

print(f"✓ Created: {normal_file}")
time.sleep(1)

# إعادة تسمية بامتداد مشبوه
suspicious_file = normal_file + ".locked"
os.rename(normal_file, suspicious_file)

print(f"✓ Renamed to: {suspicious_file}")
print("\n✅ Test file created!")
print(f"📂 Check directory: {test_dir}")
print("\nThis should trigger detection if monitoring is active!")
```

شغّله:
```bash
python quick_test.py
```

---

### الخطوة 8️⃣: التحقق من الكود

تأكد من وجود هذه الأجزاء في كودك:

#### في `main.py`:
```python
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
```

#### في `start_monitoring()`:
```python
self.observer = Observer()
self.observer.schedule(event_handler, directory, recursive=True)
self.observer.start()
```

#### في `FileSystemEventHandler`:
```python
class RansomwareEventHandler(FileSystemEventHandler):
    def on_moved(self, event):
        # تحقق من الامتدادات المشبوهة
        if event.dest_path.endswith('.locked'):
            # أطلق تنبيه!
            pass
```

---

### الخطوة 9️⃣: اختبار نهائي شامل

```bash
# 1. شغّل الفحص التشخيصي
python diagnostic_check.py

# 2. شغّل مراقب الاختبار
python test_monitoring_debug.py

# في terminal آخر:

# 3. شغّل محاكي السلوك
python test_ransomware_behavior.py

# 4. شغّل البرنامج الرئيسي
python main.py
```

**النتيجة المتوقعة:**
- ✅ terminal 1: يعرض أحداث الملفات
- ✅ البرنامج الرئيسي: يعرض الكشف في Live Events

---

### 🆘 إذا ما زال لا يعمل

قم بتشغيل هذه الأوامر وأرسل النتائج:

```bash
# معلومات النظام
python --version
pip list | findstr -i "watchdog pyqt5 psutil"

# اختبار watchdog
python -c "from watchdog.observers import Observer; print('Watchdog OK')"

# فحص المجلدات
dir logs
dir quarantine
dir src
```

---

### ✅ قائمة التحقق النهائية

- [ ] تشغيل `diagnostic_check.py` - كل الفحوصات نجحت؟
- [ ] تشغيل `test_monitoring_debug.py` - يعرض الأحداث؟
- [ ] تشغيل `test_ransomware_behavior.py` - ينشئ ملفات؟
- [ ] البرنامج الرئيسي يعمل - START MONITORING نشط؟
- [ ] المجلدات مضافة في Settings؟
- [ ] السجلات تُكتب في `logs/`؟
- [ ] Live Events يعرض الأحداث؟

إذا كانت كل الإجابات **نعم** ✅ - الكشف يعمل بنجاح! 🎉

---

### 📞 نصائح إضافية

1. **تأكد من تشغيل البرنامج من مجلد المشروع:**
   ```bash
   cd c:\Users\(-_\Pictures\RansomwareDefenseKit
   ```

2. **استخدم البيئة الافتراضية:**
   ```bash
   .venv\Scripts\activate
   ```

3. **تحديث المكتبات:**
   ```bash
   pip install --upgrade watchdog PyQt5 psutil
   ```

4. **امسح السجلات القديمة:**
   ```bash
   del logs\*.jsonl
   del logs\*.csv
   ```

---

**الآن جرّب الخطوات بالترتيب!** 🚀
