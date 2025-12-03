# app.py
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, jsonify
import time
import os

# =================================================================
# 1. ANALİZ MANTIĞINI İÇE AKTARMA
# =================================================================

# analysis_logic dosyasından tüm analiz mantığını içeren ana fonksiyonu içeri aktar
# NOT: Bu bloğu, uygulamanın analysis_logic.py olmadan çökmesini engellemek için koruyoruz.
try:
    from analysis_logic import run_full_sms_analysis
except ImportError as e:
    # Eğer import başarısız olursa (örneğin analysis_logic.py eksikse veya yanlış isimdeyse),
    # güvenli bir fallback fonksiyonu tanımlıyoruz.
    print(f"UYARI: run_full_sms_analysis yüklenemedi. analysis_logic.py dosyasını kontrol edin. Hata: {e}")


    # Simülasyon/Fallback Fonksiyonu (Hata durumunda arayüze dönecek güvenli cevap)
    def run_full_sms_analysis(number, sms_text):
        return {
            "finalRiskPct": 10.0,
            "level": "HATA - ANALİZ YÜKLENEMEDİ",
            "color": "#FF6347",  # Yumuşak Kırmızı (Soft Danger)
            "finalReasons": [
                "Kritik analiz motoru (analysis_logic.py) yüklenemedi. Dosya adını ve fonksiyon tanımını kontrol edin."]
        }

app = Flask(__name__)


# =================================================================
# 2. FLASK ROTLARI
# =================================================================

@app.route("/", methods=["GET"])
def index():
    """Ana sayfa: HTML arayüzünü yükler."""
    # Zarif Pastel tasarımlı index.html dosyasını templates klasöründen render et
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Analiz API'si: Frontend'den gelen JSON'ı işler ve sonucu JSON olarak döndürür.
    """
    if not request.is_json:
        # 400 Bad Request
        return jsonify({"error": "İstek gövdesi JSON olmalı (Content-Type: application/json)."}), 400

    # JSON verisini al, hata olursa (örneğin boş gövde) boş sözlük kullan
    data = request.get_json(silent=True) or {}
    number = (data.get("number") or "").strip()
    sms_text = (data.get("sms_text") or "").strip()

    if not sms_text:
        # 400 Bad Request
        return jsonify({"error": "Lütfen SMS içeriğini girin."}), 400

    # Payload Kısıtlaması
    if len(sms_text) > 5000:
        # 413 Payload Too Large
        return jsonify({"error": "SMS metni çok uzun (maks. 5000 karakter)."}), 413

    try:
        # İş mantığını çağır (run_full_sms_analysis fonksiyonunu kullanır)
        result_object = run_full_sms_analysis(number, sms_text)

        # Demo amaçlı küçük gecikme (arayüze akıcılık katmak için)
        time.sleep(0.5)

        # Sonuç, run_full_sms_analysis'in döndürdüğü dict olmalıdır.
        result_payload = result_object

        return jsonify(result_payload), 200

    except Exception as e:
        # ANALİZ MANTIĞININ KENDİSİNDE OLUŞAN KRİTİK HATALAR (500 Internal Server Error)
        error_detail = str(e)
        print(f"ANALİZ SIRASINDA KRİTİK HATA: {error_detail}")

        # Kullanıcıya sadece ilk 100 karakteri göster
        safe_detail = error_detail[:100] + ("..." if len(error_detail) > 100 else "")

        return jsonify({
            "finalRiskPct": 99.9,
            "level": "SİSTEM HATASI",
            "color": "#E74C3C",  # Kesin Kırmızı
            "finalReasons": [f"Analiz motoru beklenmedik bir hata ile durdu.", f"Detay: {safe_detail}"]
        }), 500


@app.route("/healthz", methods=["GET"])
def healthz():
    """Basit sağlık kontrolü endpoint'i."""
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    # Flask uygulamasını çalıştırma
    # Prod’da debug=False ve bir WSGI sunucusu (gunicorn/uwsgi) kullanın.
    app.run(debug=True)