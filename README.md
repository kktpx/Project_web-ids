# Web IDS Project 🛡️

โปรเจกต์นี้คือระบบ Web Intrusion Detection System (Web IDS) ที่ใช้ Machine Learning ในการตรวจจับการโจมตีเว็บแอปพลิเคชัน (เช่น SQL Injection, XSS) โดยระบบประกอบด้วย 2 ส่วนหลัก:

1. **`app.py` (Web IDS & Dashboard):** เป็น API สำหรับรับข้อมูล Payload มาวิเคราะห์ด้วยโมเดล ML (Scikit-Learn) และแสดงผล Log ผ่านหน้า Dashboard
2. **`todo_app.py` (Vulnerable Test App):** เป็นเว็บจำลอง (Todo List) ที่มีช่องโหว่ เพื่อใช้สำหรับทดสอบยิง Payload ใส่ระบบ และส่งข้อมูลไปตรวจที่ `app.py`

## โครงสร้างและการตั้งค่าฐานข้อมูล
ระบบใช้ SQLite เป็นฐานข้อมูล 
- ได้รับการปรับแต่งให้รองรับการ Deploy บน Serverless Platforms (เช่น Vercel, Render) โดยอัตโนมัติ (จะสลับไปเขียนไฟล์ใน `/tmp/` หากตรวจพบ Environment Variable `VERCEL=1`)

## วิธีการ Deploy ขึ้น Server (ฟรี)

### 1. Render (แนะนำสำหรับโปรเจกต์ Python)
โปรเจกต์นี้ได้เพิ่ม `gunicorn` ไว้ใน `requirements.txt` แล้ว
1. สร้าง **Web Service** บน Render
2. เลือกเชื่อมต่อกับ GitHub Repository ของคุณ
3. กำหนด Build Command: `pip install -r requirements.txt`
4. กำหนด Start Command: `gunicorn app:app` (สำหรับตัว IDS)

### 2. Vercel (สำหรับการทดสอบรวดเร็ว)
โปรเจกต์นี้มาพร้อมกับไฟล์ `vercel.json` สามารถนำไปผูกกับ GitHub และ Deploy บน Vercel ได้ทันที
*หมายเหตุ: ข้อมูล Database บน Vercel จะถูกรีเซ็ตเมื่อแอปไม่มีการใช้งานตามข้อจำกัดของ Serverless File System*

## การรันทดสอบในเครื่อง (Local) หรือเว็บเป้าหมาย

1. **เปิดรันแอปพลิเคชันทดสอบ (Todo App):**
   ```bash
   python todo_app.py
   ```
   (ระบบจะรันที่ `http://127.0.0.1:5001`)

**หมายเหตุเกี่ยวกับการทดสอบส่งข้อมูลเข้า IDS:**
ค่าดีฟอลต์ใน `todo_app.py` ได้ถูกตั้งค่าให้ชี้ไปที่ Web IDS บนคลาวด์ของคุณแล้ว (`https://project-web-ids.onrender.com/detect`) 
คุณสามารถรันเว็บจำลองในคอมพิวเตอร์ของคุณเอง แล้วยิง SQL Injection ได้เลย ข้อมูลจะถูกส่งตรงไปบันทึกลง Dashboard ใน Render ทันที!
