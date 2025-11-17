==============================
Web App Fuzzer - PyQt5 GUI (TXT Version)
ENGLISH SECTION

Web App Fuzzer - PyQt5 GUI

This project is an educational web application fuzzer built with PyQt5. It sends different attack payloads (XSS, SQL Injection, Path Traversal, Command Injection) to a target URL and analyzes the response.

Main Features:

Full PyQt5 graphical interface

Live logging during scanning

Colored results table with emojis

Reflection detection (checks if payload appears in output)

Error signature detection (SQL errors, PHP errors, Python traceback, etc.)

Response length delta analysis

JSON and CSV export support

Support for custom payload files

Payload Types:

XSS

SQL Injection

Path Traversal

Command Injection

Installation:

pip install PyQt5 requests


Run:

python web_app_fuzzer_pyqt5.py


Warning:
This tool is for educational and authorized penetration testing only.
Do NOT use it on systems you do not own or do not have permission to test.

==============================
بخش فارسی

Web App Fuzzer - PyQt5 GUI

این پروژه یک فازر آموزشی برای تست امنیت وب است که با PyQt5 ساخته شده. این ابزار انواع ورودی‌های مخرب (XSS، SQL Injection، Path Traversal، Command Injection) را به یک URL هدف ارسال می‌کند و پاسخ سرور را تحلیل می‌کند.

ویژگی‌ها:

رابط گرافیکی کامل با PyQt5

لاگ زنده در زمان فازینگ

جدول نتایج با رنگ‌بندی و ایموجی

تشخیص بازتاب Payload در HTML

تشخیص خطاهای SQL، PHP، Python

تحلیل اختلاف حجم پاسخ نسبت به baseline

خروجی‌گیری JSON و CSV

پشتیبانی از فایل Payload دلخواه

انواع Payload:

XSS

SQL Injection

Path Traversal

Command Injection

نصب:

pip install PyQt5 requests


اجرا:

python web_app_fuzzer_pyqt5.py


⚠️ هشدار:
استفاده از این ابزار فقط برای اهداف آموزشی و تست نفوذ مجاز است.
استفاده روی هر سیستم بدون اجازه قانونی، کاملاً غیرقانونی است.
