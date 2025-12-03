🌌 Nova-Web
<p align="center"> <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge"/> <img src="https://img.shields.io/badge/Python-3.10-blue?style=for-the-badge"/> <img src="https://img.shields.io/badge/Flask-Framework-black?style=for-the-badge&logo=flask"/> </p> <p align="center"> Nova-Web, SMS/metin analizini web arayüzü üzerinden gerçekleştiren modern bir NLP tabanlı projedir. Kullanıcı dostu arayüzü, hızlı sonuç veren Flask API yapısı ve eğitilmiş ML modeliyle gerçek zamanlı spam tespiti sağlar. </p>
✨ Öne Çıkanlar

🔥 Gerçek zamanlı SMS sınıflandırma

🎨 Şık ve sade web arayüzü

⚡ Hafif & hızlı Flask altyapısı

🧠 NLP tabanlı spam tespit modeli

📡 JSON API destekli uç nokta

📁 Modüler dosya yapısı — geliştirmeye çok uygun

🖥️ Demo

Projenin demo dosyası için ekran görüntüsü aşağıda gösterilmiştir:

![Demo Görseli](./demoNova.png)

Demo dosyasını indirmek için [buraya tıklayabilirsiniz](./demoNova.pbg).



🧰 Teknolojiler
Alan	Teknoloji
Backend	Flask, Python
Frontend	HTML, CSS, JavaScript
ML / NLP	Scikit-learn, Vectorizer, Model Pipeline
Ortam	venv (Virtual Environment)
📂 Proje Yapısı
nova-web/
│
├── app.py                 # Flask API + routing
├── static/
│   ├── style.css          # Tasarım
│   └── script.js          # Dinamik işlemler
├── templates/
│   └── index.html         # Arayüz
├── model/
│   ├── spam_model.pkl     # Eğitilmiş ML modeli
│   └── vectorizer.pkl     # NLP vectorizer
│
├── requirements.txt
└── README.md

🚀 Kurulum
1️⃣ Depoyu klonla
git clone https://github.com/fnur21/nova-web.git
cd nova-web

2️⃣ Sanal ortam oluştur
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate

3️⃣ Gereksinimleri kur
pip install -r requirements.txt

4️⃣ Çalıştır
python app.py


📍 Aç:
http://127.0.0.1:5000

🌐 API Endpoint
POST → /analyze

İstek:

{
  "sms_text": "Analiz edilecek mesaj"
}


Yanıt:

{
  "prediction": "spam",
  "confidence": 0.92
}

🛠️ Geliştirme Fikirleri

Kullanıcı geçmişini kaydetme

Çoklu model desteği (SVM, RF, Logistic Regression)

Dashboard oluşturma

Mobil uyumlu modern UI

Çoklu dil desteği

👩‍💻 Geliştirici

Fatma Nur Pekmez
Bilgisayar Mühendisliği — Niğde Ömer Halisdemir Üniversitesi
GitHub: fnur21

📄 Lisans

MIT Lisansı ile yayınlanmıştır.
