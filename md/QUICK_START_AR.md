# 🚀 تعليمات التشغيل والاختبار السريع

## ✅ تشغيل الفحص التشخيصي (ابدأ هنا!)

```powershell
cd c:\Users\(-_\Pictures\RansomwareDefenseKit
python diagnostic_check.py
```

سيفحص كل شيء ويخبرك بالضبط ما المشكلة!

---

## 🔧 إصلاح المشاكل

إذا قال الفحص أن watchdog مفقود:

```powershell
pip install watchdog
```

إذا قال PyQt5 مفقود:

```powershell
pip install PyQt5
```

تثبيت كل شيء مرة واحدة:

```powershell
pip install watchdog PyQt5 psutil
```

---

## 🧪 اختبار الكشف (بدون البرنامج)

### الطريقة 1: مراقب بسيط

```powershell
# Terminal 1
python test_monitoring_debug.py
```

اترك هذا يعمل، افتح PowerShell جديد:

```powershell
# Terminal 2
cd c:\Users\(-_\Pictures\RansomwareDefenseKit2
python test_ransomware_behavior.py
```

**يجب أن ترى:**
- ✓ ملفات تُنشأ
- 🔄 ملفات تُعاد تسميتها
- 🚨 تنبيهات الكشف

---

### الطريقة 2: اختبار سريع

```powershell
python quick_test.py
```

سينشئ ملفات اختبار في `C:\Quick_Test` ويخبرك ماذا تتوقع.

---

## 🎯 تشغيل البرنامج الكامل

```powershell
python main.py
```

**في البرنامج:**
1. اذهب لتبويب **Settings**
2. أضف المجلد: `C:\Test_Quarantine`
3. اضغط **START MONITORING**
4. اذهب لتبويب **Live Events**
5. في PowerShell آخر شغّل: `python test_ransomware_behavior.py`
6. راقب الأحداث تظهر!

---

## 📋 الخطوات بالترتيب (للمبتدئين)

```powershell
# 1. انتقل للمجلد
cd c:\Users\(-_\Pictures\RansomwareDefenseKit

# 2. افحص النظام
python diagnostic_check.py

# 3. إذا كان كل شيء OK، جرّب الاختبار السريع
python quick_test.py

# 4. شغّل مراقب الاختبار
python test_monitoring_debug.py
```

في PowerShell جديد:

```powershell
# 5. شغّل محاكي السلوك
cd c:\Users\(-_\Pictures\RansomwareDefenseKit2
python test_ransomware_behavior.py
```

**إذا رأيت أحداث في Terminal 1 - الكشف يعمل!** ✅

الآن شغّل البرنامج الرئيسي:

```powershell
cd c:\Users\(-_\Pictures\RansomwareDefenseKit
python main.py
```

---

## 🐛 إذا واجهت مشاكل

راجع:
- [DETECTION_FIX.md](DETECTION_FIX.md) - دليل إصلاح شامل
- [TROUBLESHOOTING_AR.md](TROUBLESHOOTING_AR.md) - دليل بالعربي

أو شغّل:

```powershell
python diagnostic_check.py > results.txt
notepad results.txt
```

---

## ✅ التحقق السريع

| السؤال | الأمر | النتيجة المتوقعة |
|---------|-------|------------------|
| Python مثبت؟ | `python --version` | 3.7+ |
| watchdog مثبت؟ | `pip show watchdog` | معلومات الحزمة |
| الملفات موجودة؟ | `dir main.py` | يظهر الملف |
| السجلات موجودة؟ | `dir logs` | مجلد موجود |
| التشخيص ناجح؟ | `python diagnostic_check.py` | 7/7 PASS |

---

**ابدأ بـ `diagnostic_check.py` دائماً!** 🎯
