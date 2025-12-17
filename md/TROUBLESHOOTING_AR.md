# 🔧 دليل إصلاح مشاكل الكشف - خطوة بخطوة

## 📋 نظرة عامة

إذا كان نظام الكشف لا يعمل في تطبيق Ransomware Defense Kit، اتبع هذه الخطوات.

---

## ⚡ الحل السريع (5 دقائق)

### الخطوة 1: شغّل الفحص التشخيصي

افتح PowerShell في مجلد المشروع:

```powershell
cd c:\Users\(-_\Pictures\RansomwareDefenseKit
python diagnostic_check.py
```

**ماذا سيحدث:**
- سيفحص Python، المكتبات، الملفات، الإعدادات
- سيخبرك بالضبط ما هو المفقود
- سيعطيك تعليمات الإصلاح

### الخطوة 2: ثبّت المكتبات المفقودة

إذا ظهرت مكتبات مفقودة:

```powershell
pip install watchdog PyQt5 psutil
```

### الخطوة 3: اختبر watchdog

```powershell
python test_monitoring_debug.py
```

اترك هذا يعمل، وافتح PowerShell جديد:

```powershell
cd c:\Users\(-_\Pictures\RansomwareDefenseKit2
python test_ransomware_behavior.py
```

**النتيجة المتوقعة:**
```
✓ CREATED: C:\Test_Quarantine\document_0.txt
🔄 RENAMED: document_0.txt → document_0.txt.locked
   🚨 SUSPICIOUS EXTENSION DETECTED!
```

إذا رأيت هذا - watchdog يعمل! ✅

### الخطوة 4: اختبار سريع

```powershell
python quick_test.py
```

سينشئ ملفات اختبار ويخبرك ما يجب أن يحدث.

---

## 🔍 التشخيص المفصل

### المشكلة 1: "No module named 'watchdog'"

**الحل:**
```powershell
pip install watchdog
```

**التحقق:**
```powershell
python -c "import watchdog; print('OK')"
```

---

### المشكلة 2: البرنامج يعمل لكن لا توجد أحداث

**الأسباب المحتملة:**

#### السبب أ: المجلد غير مضاف للمراقبة
1. شغّل البرنامج: `python main.py`
2. اذهب لتبويب **Settings**
3. أضف المجلد: `C:\Test_Quarantine`
4. اضغط **Apply** أو **Save**
5. اضغط **START MONITORING**

#### السبب ب: Observer لم يبدأ
افحص الكود في ملف المراقبة:
```python
# يجب أن يحتوي على:
self.observer = Observer()
self.observer.schedule(handler, path, recursive=True)
self.observer.start()  # ⚠️ مهم جداً!
```

#### السبب ج: الصلاحيات
شغّل البرنامج كمسؤول:
```powershell
Start-Process python -ArgumentList "main.py" -Verb RunAs
```

---

### المشكلة 3: الأحداث تظهر لكن لا تطابق القواعد

**افحص ملف القواعد** (`rules.json` أو في الكود):

```json
{
  "suspicious_extensions": [".locked", ".encrypted", ".crypto"],
  "ransom_notes": ["README.txt", "DECRYPT.txt"],
  "burst_threshold": 50
}
```

**تأكد من:**
- الامتدادات صحيحة
- الأسماء بالحروف الصحيحة
- العتبات (thresholds) منطقية

---

### المشكلة 4: السجلات فارغة

**افحص مجلد logs:**
```powershell
dir logs
```

**إذا كان فارغاً:**
```powershell
# تأكد من الصلاحيات
echo test > logs\test.txt
```

إذا فشل - مشكلة صلاحيات!

**الحل:**
```powershell
# امنح صلاحيات كاملة
icacls logs /grant Users:F
```

---

### المشكلة 5: UI لا يتحدث

**تحقق من signals/slots في PyQt5:**

```python
# في GUI code
self.detection_signal = pyqtSignal(dict)
self.detection_signal.connect(self.on_detection)

# عند الكشف
self.detection_signal.emit(event_data)
```

**تأكد من:**
- Signal معرّف بشكل صحيح
- Connected قبل emit
- Slot يستقبل البيانات

---

## 🧪 سيناريوهات الاختبار

### اختبار 1: ملف واحد

```python
import os
os.makedirs("C:\\Test", exist_ok=True)
with open("C:\\Test\\file.txt", "w") as f:
    f.write("test")
os.rename("C:\\Test\\file.txt", "C:\\Test\\file.txt.locked")
```

**المتوقع:** تنبيه CRITICAL

---

### اختبار 2: ملف فدية

```python
with open("C:\\Test\\README.txt", "w") as f:
    f.write("YOUR FILES ARE LOCKED!")
```

**المتوقع:** تنبيه CRITICAL

---

### اختبار 3: نشاط مكثف

```python
for i in range(60):
    with open(f"C:\\Test\\file_{i}.dat", "wb") as f:
        f.write(b"X" * 100)
```

**المتوقع:** تنبيه WARNING (تجاوز العتبة)

---

## 📊 جدول استكشاف الأخطاء

| الأعراض | السبب المحتمل | الحل |
|---------|---------------|------|
| لا شيء يعمل | Python قديم | حدّث لـ 3.7+ |
| ImportError | مكتبة مفقودة | pip install |
| لا أحداث | المجلد غير مراقب | أضفه في Settings |
| أحداث بلا كشف | القواعد خاطئة | راجع rules.json |
| Permission denied | ليس admin | Run as Administrator |
| UI لا يتحدث | Signals معطلة | تحقق من الكود |
| سجلات فارغة | مشكلة كتابة | تحقق من الصلاحيات |

---

## ✅ قائمة التحقق النهائية

قبل أن تقول "لا يعمل"، تأكد من:

- [ ] Python 3.7+ مثبت
- [ ] watchdog مثبت: `pip show watchdog`
- [ ] PyQt5 مثبت: `pip show PyQt5`
- [ ] الملفات موجودة: `dir main.py`
- [ ] المجلدات موجودة: `dir logs`
- [ ] Config صحيح: `type config.json`
- [ ] التشخيص نجح: `python diagnostic_check.py`
- [ ] Watchdog يعمل: `python test_monitoring_debug.py`
- [ ] الملفات تُنشأ: `python quick_test.py`
- [ ] البرنامج يعمل: `python main.py`
- [ ] المراقبة نشطة: زر START أخضر
- [ ] المجلد مضاف: في Settings
- [ ] الصلاحيات كافية: Run as Admin

---

## 🆘 ما زال لا يعمل؟

قم بالتالي وأرسل النتائج:

```powershell
# 1. معلومات النظام
python --version
pip list

# 2. اختبار الاستيراد
python -c "from watchdog.observers import Observer; print('OK')"

# 3. الفحص الكامل
python diagnostic_check.py > diagnosis.txt

# 4. اختبار watchdog
python test_monitoring_debug.py
# (اتركه يعمل وشغّل test في terminal آخر)

# 5. افحص السجلات
type logs\events.jsonl
```

---

## 🎯 الخطوات الموصى بها (بالترتيب)

```powershell
# الخطوة 1: انتقل للمجلد
cd c:\Users\(-_\Pictures\RansomwareDefenseKit

# الخطوة 2: شغّل التشخيص
python diagnostic_check.py

# الخطوة 3: ثبّت ما ينقص
pip install watchdog PyQt5 psutil

# الخطوة 4: اختبر watchdog
python test_monitoring_debug.py
# اتركه يعمل...

# في terminal جديد:
cd c:\Users\(-_\Pictures\RansomwareDefenseKit2
python test_ransomware_behavior.py

# الخطوة 5: إذا نجح الاختبار، شغّل البرنامج
cd c:\Users\(-_\Pictures\RansomwareDefenseKit
python main.py
```

---

**إذا اتبعت كل الخطوات والتشخيص نجح، الكشف سيعمل 100%!** ✅

---

*تم التحديث: ديسمبر 2025*
