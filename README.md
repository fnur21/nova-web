📌 Nova-Web

Nova-Web, kullanıcıdan alınan SMS/metin içeriklerini analiz eden, spam tespiti yapan ve web arayüzü üzerinden çalışan bir uygulamadır. Arka planda Flask; ön yüzde HTML/CSS/JS kullanılır. Geliştirilmeye açık, modüler bir NLP projesidir.

🚀 Özellikler

🔎 SMS / metin analizi (spam – normal)

🌐 Kullanıcı dostu web arayüzü

🔌 JSON tabanlı API endpoint desteği

🧠 NLP + makine öğrenimi ile sınıflandırma

📁 Temiz ve modüler proje yapısı

💡 Kolay geliştirme ve model güncelleme imkanları

🧰 Kullanılan Teknolojiler
Amaç	Teknoloji
Backend	Python, Flask
Frontend	HTML, CSS, JavaScript
NLP/ML	scikit-learn, preprocessing, modelleme
Ortam	Virtual Environment (venv)
📂 Proje Yapısı
nova-web/
├── app.py                 # Flask ana uygulaması
├── static/                # CSS / JS / resimler
│   ├── style.css
│   └── script.js
├── templates/             # HTML dosyaları
│   └── index.html
├── model/                 # Eğitilmiş model + vektörizer
│   ├── spam_model.pkl
│   └── vectorizer.pkl
├── requirements.txt       # Gereken paketler
└── README.md              # Proje dokümanı


⚠️ Not: venv/ ve .idea/ klasörleri .gitignore içinde tutulur ve GitHub’a yüklenmez.

📦 Kurulum ve Çalıştırma

1️⃣ Depoyu klonlayın

git clone https://github.com/fnur21/nova-web.git
cd nova-web


2️⃣ Sanal ortam oluşturun

python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate


3️⃣ Gereksinimleri yükleyin

pip install -r requirements.txt


4️⃣ Uygulamayı başlatın

python app.py


5️⃣ Tarayıcıdan açın

http://127.0.0.1:5000

🔌 API Kullanımı

POST /analyze

Gönderilen JSON:

{
  "sms_text": "Analiz edilecek metin"
}


Örnek dönüş:

{
  "prediction": "spam",
  "confidence": 0.87
}

🛠️ Geliştirme Önerileri

Yeni ML modeli ekleme (RandomForest, SVM vb.)

Daha gelişmiş preprocessing

Modern UI tasarımı ekleme

Unit test / API test entegrasyonu

Kullanıcıdan dosya yükleme (CSV) özelliği

👤 Geliştirici

Fatma Nur Pekmez
Niğde Ömer Halisdemir Üniversitesi — Bilgisayar Mühendisliği
GitHub: fnur21

📄 Lisans

Bu proje MIT lisansı altındadır.
