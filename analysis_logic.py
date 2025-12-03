# analysis_logic.py
# -*- coding: utf-8 -*-
#
# SMS Analiz Motoru - Tüm iş mantığı bu dosyada yer alır.
#
import re
from urllib.parse import urlparse
import requests
import socket
import ipaddress
import time

# Harici kütüphaneyi içe aktarma (Kurulmamışsa bile çökmesini önlemek için try/except kullanılır)
try:
    import phonenumbers

    HAVE_PHONENUMBERS = True
except ImportError:
    HAVE_PHONENUMBERS = False

# =================================================================
# BÖLÜM 1: SABİTLER ve USOM İŞLEMLERİ
# =================================================================

USOM_BASE_URL = "https://www.usom.gov.tr/api/address/index"
USOM_API_KEY = ""


def fetch_usom_blocklist(max_pages=5, timeout_sec=6):
    """USOM'dan zararlı alan adı, IP ve ağ listelerini çeker."""
    bad_domains = set()
    bad_ips = set()
    bad_networks = []

    headers = {}
    if USOM_API_KEY:
        headers["Authorization"] = f"Bearer {USOM_API_KEY}"

    for page in range(1, max_pages + 1):
        try:
            resp = requests.get(
                USOM_BASE_URL,
                params={"page": page},
                timeout=timeout_sec,
                headers=headers if headers else None,
            )
            if resp.status_code != 200: break
            js = resp.json()
            data_list = (js.get("data") or js.get("models") or js.get("items") or [])
            if not data_list: break

            for row in data_list:
                addr = (row.get("address") or row.get("url") or row.get("domain") or row.get("ip"))
                if not addr: continue

                a = str(addr).strip().lower().strip(".,;:!?)(")
                if a.startswith("http://") or a.startswith("https://"):
                    parsed = urlparse(a)
                    host = (parsed.netloc or "").lower()
                    if host: a = host

                try:
                    if "/" in a:
                        net = ipaddress.ip_network(a, strict=False)
                        bad_networks.append(net);
                        continue
                    ip_obj = ipaddress.ip_address(a)
                    bad_ips.add(str(ip_obj));
                    continue
                except Exception:
                    pass

                host_only = a.split(":")[0]
                if host_only:
                    bad_domains.add(host_only)
        except Exception:
            # Hata durumunda (zaman aşımı/bağlantı) döngüyü kır
            break
    return {"domains": bad_domains, "ips": bad_ips, "networks": bad_networks}


# =================================================================
# BÖLÜM 2: TELEFON NUMARASI ANALİZİ
# =================================================================

FALLBACK_COUNTRY_CODES = {
    1, 7, 20, 27, 30, 31, 32, 33, 34, 36, 39, 40, 41, 43, 44, 45, 46, 47, 48, 49, 51, 52, 53, 54, 55,
    56, 57, 58, 60, 61, 62, 63, 64, 65, 66, 81, 82, 84, 86, 90, 91, 92, 93, 94, 95, 98, 211, 212, 213,
    216, 218, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235,
    236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 248, 249, 250, 251, 252, 253, 254,
    255, 256, 257, 258, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 290, 291, 297, 298,
    299, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 370, 371, 372, 373, 374, 375, 376,
    377, 378, 379, 380, 381, 382, 385, 386, 387, 389, 420, 421, 423, 500, 501, 502, 503, 504,
    505, 506, 507, 508, 509, 590, 591, 592, 593, 594, 595, 596, 597, 598, 599, 670, 672, 673,
    674, 675, 676, 677, 678, 679, 680, 681, 682, 683, 685, 686, 687, 688, 689, 690, 691, 692,
    850, 852, 853, 855, 856, 870, 871, 872, 873, 874, 880, 881, 882, 883, 886, 888, 960, 961,
    962, 963, 964, 965, 966, 967, 968, 970, 971, 972, 973, 974, 975, 976, 977, 992, 993, 994,
    995, 996, 998
}
COUNTRY_NUMBER_LENGTHS = {
    90: (10,), 49: (10, 11), 44: (9, 10), 33: (9,), 34: (9,), 39: (9, 10, 11), 31: (9,), 32: (8, 9),
    30: (10,), 351: (9,), 352: (8, 9), 353: (9,), 354: (7,), 355: (8, 9), 356: (8,), 357: (8,),
    358: (9, 10), 359: (8, 9), 370: (8, 9), 371: (8,), 372: (7, 8), 373: (8,), 374: (8, 9),
    375: (9,), 376: (6,), 377: (8, 9), 378: (10,), 380: (9,), 381: (8, 9), 382: (8, 9), 385: (8, 9),
    386: (8, 9), 387: (8, 9), 389: (8, 9), 420: (9,), 421: (9,), 423: (7,), 1: (10,), 52: (10,),
    55: (10, 11), 54: (10,), 56: (9,), 57: (10,), 58: (10, 11), 81: (10,), 82: (9, 10),
    84: (9, 10, 11), 86: (10, 11), 91: (10,), 92: (10,), 93: (9,), 94: (9,), 95: (8, 9), 98: (10,),
    971: (8, 9), 966: (8, 9), 965: (8,), 974: (8,), 968: (8,), 970: (8, 9), 972: (8, 9), 964: (9, 10),
    963: (8, 9), 962: (8, 9), 961: (7, 8), 960: (7,), 20: (9, 10), 212: (9,), 213: (8, 9),
    216: (8,), 218: (8, 9), 234: (8, 9, 10, 11), 27: (9,), 61: (9,), 64: (8, 9, 10)
}


def normalize_number(n: str) -> str:
    """Telefon numarasını temizler ve uluslararası formata (varsa) hazırlar."""
    if not n: return ""
    n = re.sub(r"[()\-\s]", "", n.strip())
    if n.startswith("00"): n = "+" + n[2:]
    return n


def check_length_feedback(country_code: int, nsn: str):
    """Ülke koduna göre numara uzunluğunu kontrol eder."""
    if not nsn.isdigit():
        return False, "Numarada rakam dışı karakter var."
    if country_code in COUNTRY_NUMBER_LENGTHS:
        allowed = COUNTRY_NUMBER_LENGTHS[country_code]
        if len(nsn) in allowed:
            return True, f"uzunluk makul ({len(nsn)} hane)."
        typical = allowed[0];
        diff = len(nsn) - typical
        if diff > 0:
            return False, (f"tipik uzunluk {typical} hane ama {len(nsn)} hane geldi. "
                           f"{diff} fazla rakam var.")
        else:
            return False, (f"tipik uzunluk {typical} hane ama {len(nsn)} hane geldi. "
                           f"{abs(diff)} rakam eksik (şüpheli/sahte olabilir).")
    else:
        if 4 <= len(nsn) <= 12:
            return True, f"uzunluk {len(nsn)} hane (genel kabul aralığında)."
        elif len(nsn) < 4:
            return False, f"çok kısa ({len(nsn)} hane). Tahminen {4 - len(nsn)} hane daha kısa."
        else:
            return False, f"çok uzun ({len(nsn)} hane). Tahminen {len(nsn) - 12} hane fazla."


def parse_country_code_fallback(n: str):
    """Uluslararası kod yoksa +90 varsayıp ülke kodunu ayırmaya çalışır."""
    if not (n and n.startswith("+") and len(n) > 1): return None, None
    s = n[1:]
    for length in (1, 2, 3):
        if len(s) >= length and s[:length].isdigit():
            code = int(s[:length])
            if code in FALLBACK_COUNTRY_CODES:
                nsn = re.sub(r"\D", "", s[length:])
                return code, nsn
    return None, None


def classify_phone(number: str):
    """Telefon numarasını TR/Yurtdışı/Geçersiz olarak sınıflandırır."""
    n = normalize_number(number)
    if not n:
        return {"valid": False, "is_tr": False, "is_foreign": False, "country_code": None, "normalized": None,
                "reason": "Numara girilmedi."}

    if not n.startswith("+"):
        if re.fullmatch(r"0?5\d{9}", n):  # Basit TR mobil kontrolü
            normalized = "+90" + n[-10:]
            cc = 90
            nsn = normalized[1 + len(str(cc)):]
            ok, fb = check_length_feedback(cc, nsn)
            if not ok:
                return {"valid": False, "is_tr": True, "is_foreign": False, "country_code": cc, "normalized": None,
                        "reason": fb}
            return {"valid": True, "is_tr": True, "is_foreign": False, "country_code": cc, "normalized": normalized,
                    "reason": "TR mobil numarası. " + fb}
        return {"valid": False, "is_tr": False, "is_foreign": False, "country_code": None, "normalized": None,
                "reason": "Numara uluslararası (+90 gibi) formatta değil."}

    # phonenumbers kütüphanesi kuruluysa, daha iyi doğrulama dene
    if HAVE_PHONENUMBERS:
        try:
            pn = phonenumbers.parse(n, None)
            cc = getattr(pn, "country_code", None)
            if cc:
                s = re.sub(r"^\+?%d" % cc, "", n)
                nsn = re.sub(r"\D", "", s)
                ok, fb = check_length_feedback(cc, nsn)
                if not phonenumbers.is_possible_number(pn):
                    return {"valid": False, "is_tr": (cc == 90), "is_foreign": (cc != 90), "country_code": cc,
                            "normalized": n if ok else None, "reason": "Numara şüpheli: " + fb}
                if not ok:
                    return {"valid": False, "is_tr": (cc == 90), "is_foreign": (cc != 90), "country_code": cc,
                            "normalized": None, "reason": fb}

                if cc == 90:
                    return {"valid": True, "is_tr": True, "is_foreign": False, "country_code": cc, "normalized": n,
                            "reason": "TR numarası. " + fb}
                return {"valid": True, "is_tr": False, "is_foreign": True, "country_code": cc, "normalized": n,
                        "reason": f"Yurtdışı numarası (+{cc}). " + fb}
        except Exception:
            pass  # phonenumbers hatası, fallback'e geç

    # Fallback yol
    cc, nsn = parse_country_code_fallback(n)
    if cc is None:
        return {"valid": False, "is_tr": False, "is_foreign": False, "country_code": None, "normalized": None,
                "reason": "Geçersiz ülke kodu (+00 vb.) veya tanınmayan format."}
    ok, fb = check_length_feedback(cc, nsn)
    if not ok:
        return {"valid": False, "is_tr": (cc == 90), "is_foreign": (cc != 90), "country_code": cc, "normalized": None,
                "reason": fb}

    if cc == 90:
        return {"valid": True, "is_tr": True, "is_foreign": False, "country_code": cc, "normalized": n,
                "reason": "TR numarası. " + fb}
    return {"valid": True, "is_tr": False, "is_foreign": True, "country_code": cc, "normalized": n,
            "reason": f"Yurtdışı numarası (+{cc}). " + fb}


# =================================================================
# BÖLÜM 3: METİN VE LİNK ANALİZİ SABİTLERİ VE FONKSİYONLARI
# =================================================================

SUSPICIOUS_TLDS = {"ru", "cn", "cfd", "top", "xyz", "lol", "click", "link", "icu", "rest", "win", "bet"}
TRUSTED_TLDS = {"gov.tr", "mil.tr", "edu.tr", "bel.tr", "k12.tr", "gov", "edu", "mil", "gouv.fr", "gov.uk"}

PHISH_OFFICIAL_WORDS = [
    "ptt", "mng kargo", "yurtiçi kargo", "yurtici kargo", "arçelik", "arcelik", "ziraat",
    "vakıfbank", "vakifbank", "halkbank", "garanti", "is bankasi", "iş bankası", "is bankası",
    "e-devlet", "edevlet", "turkcell", "vodafone", "turk telekom", "hesabınız bloke",
    "hesabiniz bloke", "kartınız bloke", "kartiniz bloke", "şifrenizi girin",
    "sifrenizi girin", "şifrenizi doğrulayın", "sifrenizi dogrulayin",
    "kimlik doğrulama", "kimlik dogrulama", "tc kimlik", "tckn", "şifreniz kilitlendi",
    "sifreniz kilitlendi"
]
LEGAL_PRESSURE_WORDS = [
    "icra", "haciz", "yasal işlem", "yasal islem", "dava açılacaktır", "dava acilacaktir",
    "icra takibi", "dosya takibi", "borcunuz", "borcunuzu", "ödemeniz gecikmiştir",
    "odemeniz gecikmistir", "son uyarı", "son uyari", "takip başlatılacaktır",
    "takip baslatilacaktir", "avukat", "hukuki işlem", "hukuki islem"
]
MONEY_DEMAND_WORDS = [
    "iban", "eft", "havale", "para", "gönder", "gonder", "ödeme", "odeme",
    "ücret", "ucret", "yatır", "yatir", "btc", "kripto", "crypto", "usdt",
    "ödeme linki", "odeme linki", "hesaba aktar", "hesabina aktar"
]
GAMBLING_SPAM_WORDS = [
    "bahis", "casino", "slot", "rulet", "iddaa", "canlı bahis", "canli bahis",
    "yasal olmayan bahis", "kaçak bahis", "kacak bahis",
    "bonus", "hosgeldin bonusu", "hoşgeldin bonusu",
    "%100 bonus", "%200 bonus", "%300 bonus", "%400 bonus",
    "free spin", "fs", "free bonus", "ilk yatırımınıza", "ilk yatiriminiza",
    "şans bonusu", "sans bonusu", "çekim limiti", "cekim limiti",
    "2 saatte", "2 saat içinde", "hemen kazan", "anında kazanç", "aninda kazanc",
    "500 tl kazan", "1000 tl kazan", "10 milyon çekim limiti", "10 milyon cekim limiti"
]
URGENCY_WORDS = [
    "hemen", "acil", "24 saat içinde", "24 saat icinde", "derhal", "şu anda", "su anda",
    "acilen", "anında", "aninda", "hemen öde", "hemen ode", "şimdi öde", "simdi ode",
    "sadece bugün", "sadece bugun", "son şans", "son sans", "kalan son hak", "kalan son hakkiniz"
]

URL_PATTERNS = [r"http[s]?://[^\s]+", r"\bbit\.ly\b", r"\btinyurl\.com\b", r"\bgoo\.gl\b", r"\bqr\.ae\b"]
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_LIKE_RE = re.compile(r"\b[A-Za-z0-9\-_]{1,63}\.[A-Za-z]{1,24}\b")


def extract_word_tokens_for_semantic_check(msg: str):
    lowered = msg.lower()
    tmp = lowered
    for pat in URL_PATTERNS:
        tmp = re.sub(pat, " ", tmp, flags=re.IGNORECASE)
    tmp = re.sub(IP_RE, " ", tmp)
    tmp = re.sub(DOMAIN_LIKE_RE, " ", tmp)
    words = re.findall(r"[a-zA-ZçğıöşüÇĞİÖŞÜ0-9%]+", tmp)
    return words


def any_keyword(words, keywords):
    wl = [w.lower() for w in words]
    for kw in keywords:
        parts = kw.split()
        if len(parts) == 1:
            if kw in wl:
                return True
        else:
            joined = " ".join(wl)
            if kw in joined:
                return True
    return False


def analyze_text_content_risk(number: str, sms_text: str):
    """SMS içeriğindeki kelime ve kalıp risklerini puanlar."""
    text_lower = (sms_text or "").lower().strip()
    words = extract_word_tokens_for_semantic_check(sms_text)

    risk_points = 0.0
    reasons = []
    phone_info = classify_phone(number)

    if phone_info["valid"] and phone_info["is_foreign"]:
        risk_points += 25;
        reasons.append("Numara yurtdışı formatında (+90 dışı).")
    elif number.strip() and not phone_info["valid"]:
        risk_points += 20;
        reasons.append("Numara format/uzunluk şüpheli: " + phone_info["reason"])

    has_money = any_keyword(words, MONEY_DEMAND_WORDS)
    has_legal = any_keyword(words, LEGAL_PRESSURE_WORDS)
    has_official = any_keyword(words, PHISH_OFFICIAL_WORDS)
    has_urgency = any_keyword(words, URGENCY_WORDS)
    has_gamble = any_keyword(words, GAMBLING_SPAM_WORDS)

    if has_money:  risk_points += 35; reasons.append("Para transferi / IBAN / ödeme talebi tespit edildi.")
    if has_legal:  risk_points += 50; reasons.append("İcra / haciz / yasal işlem tehdidi var.")
    if has_official: risk_points += 15; reasons.append(
        "Resmi kurum / banka / operatör adı anılıyor (kimlik avı olabilir).")
    if has_urgency: risk_points += 15; reasons.append("Acil / hemen yap baskısı var.")
    if has_gamble: risk_points += 30; reasons.append("Bahis / kumar / hızlı kazanç / bonus vaatleri tespit edildi.")

    if phone_info["valid"] and phone_info["is_foreign"] and (has_money or has_legal or has_gamble):
        if risk_points < 80: risk_points = 80
        reasons.append("Yurtdışı numaradan para / tehdit / bahis odaklı mesaj (yüksek risk).")

    all_caps = (sms_text.strip() == sms_text.strip().upper() and len(sms_text.strip()) >= 4)
    token_count = len(text_lower.split())
    if token_count <= 5 and (has_money or has_legal or has_gamble):
        risk_points += 15;
        reasons.append("Mesaj çok kısa ama para/tehdit/hızlı kazanç içeriyor (spam tarzı).")
    if all_caps and (has_money or has_legal or has_gamble):
        risk_points += 10;
        reasons.append("Tamamen büyük harfli agresif dil kullanıyor.")
    if (has_money and has_legal) and risk_points < 85:
        risk_points = 85;
        reasons.append("Para talebi ile yasal tehdit birlikte (klasik dolandırıcılık paterni).")
    if has_gamble and risk_points < 70:
        risk_points = 70;
        reasons.append("Gerçekçi olmayan kazanç / bonus vaadi (yüksek risk).")

    if not reasons:
        reasons = ["Belirgin tehdit, para talebi, bahis/kumar ya da kimlik avı dili saptanmadı."]

    content_risk_pct = max(0.0, min(100.0, risk_points))

    flags = {
        "phone_info": phone_info,
        "has_money": has_money,
        "has_legal": has_legal,
        "has_official": has_official,
        "has_urgency": has_urgency,
        "has_gamble": has_gamble,
        "all_caps": all_caps,
        "token_count": token_count,
    }
    return content_risk_pct, reasons, flags


def extract_domain(raw_url: str) -> str:
    """URL'den veya domain benzeri string'ten temiz domain/IP çeker."""
    raw_url = raw_url.strip(".,;:!?)(")
    if raw_url.lower().startswith("http://") or raw_url.lower().startswith("https://"):
        host = (urlparse(raw_url).netloc or "").lower()
        return host
    if IP_RE.fullmatch(raw_url):
        return raw_url
    if " " not in raw_url and "." in raw_url:
        return raw_url.lower()
    return ""


def find_urls_and_domains(text: str):
    """Metin içindeki tüm URL, IP ve domain benzeri yapıları bulur."""
    out = []
    t = text or ""
    for pat in URL_PATTERNS:
        for m in re.finditer(pat, t, flags=re.IGNORECASE):
            out.append({'match': m.group(0), 'type': 'http_or_known'})
    for m in IP_RE.finditer(t):
        out.append({'match': m.group(0), 'type': 'ip'})
    IGNORE_SHORTS = {'e.g', 'i.e', 'vs', 'mr', 'ms', 'dr'}
    for m in DOMAIN_LIKE_RE.finditer(t):
        s = m.group(0).strip(".,;:!?)(")
        left, _, right = s.partition('.')
        if left.lower() in IGNORE_SHORTS:
            continue
        if len(s) >= 3 and len(left) >= 1 and len(right) >= 1:
            if not any(d['match'].lower() == s.lower() for d in out):
                out.append({'match': s, 'type': 'domain_like'})
    return out


def analyze_link_risk(sms_text: str, usom_blocklist: dict):
    """Linkleri analiz eder ve USOM listeleriyle karşılaştırır."""
    urls = find_urls_and_domains(sms_text)
    link_found = len(urls) > 0
    if not link_found:
        return 0.0, ["Mesajda link tespit edilmedi."], False

    link_risk_pct = 0.0
    link_reasons = []
    domains_seen = set()
    ips_seen = set()

    for u in urls:
        d = extract_domain(u["match"])
        if not d: continue
        if IP_RE.fullmatch(d):
            ips_seen.add(d)
        else:
            domains_seen.add(d.split(":")[0])

    bad_domains = usom_blocklist.get("domains", set())
    bad_ips = usom_blocklist.get("ips", set())
    bad_networks = usom_blocklist.get("networks", [])

    resolved_info = [];
    resolved_bad_info = []
    for dom in list(domains_seen):
        try:
            ip_addr = socket.gethostbyname(dom)
            if ip_addr:
                ips_seen.add(ip_addr)
                resolved_info.append(f"{dom} -> {ip_addr}")
                if ip_addr in bad_ips:
                    resolved_bad_info.append(f"{dom} -> {ip_addr}")
                else:
                    try:
                        ipobj = ipaddress.ip_address(ip_addr)
                        for net in bad_networks:
                            if ipobj in net:
                                resolved_bad_info.append(f"{dom} -> {ip_addr} ({net})")
                                break
                    except Exception:
                        pass
        except Exception:
            pass

    bad_domain_hits = [d for d in domains_seen if d in bad_domains]
    bad_ip_hits = [ip for ip in ips_seen if ip in bad_ips]

    bad_ip_cidr_hits = []
    for ip_ in ips_seen:
        try:
            ipobj = ipaddress.ip_address(ip_)
            for net in bad_networks:
                if ipobj in net:
                    bad_ip_cidr_hits.append(f"{ip_} ({net})");
                    break
        except Exception:
            pass

    # USOM KRİTİK KURALI
    if bad_domain_hits or bad_ip_hits or bad_ip_cidr_hits or resolved_bad_info:
        link_risk_pct = 100.0
        if bad_domain_hits:
            link_reasons.append("USOM zararlı alan adı eşleşmesi: " + ", ".join(sorted(set(bad_domain_hits))))
        if bad_ip_hits:
            link_reasons.append("Mesajdaki/çözümlenen IP USOM kara listesinde: " + ", ".join(sorted(set(bad_ip_hits))))
        if bad_ip_cidr_hits:
            link_reasons.append(
                "Mesajdaki/çözümlenen IP USOM zararlı CIDR aralığında: " + ", ".join(sorted(set(bad_ip_cidr_hits))))
        if resolved_bad_info:
            link_reasons.append(
                "Alan adı -> IP eşleşmesi USOM listesinde: " + ", ".join(sorted(set(resolved_bad_info))))
        if resolved_info:
            link_reasons.append("Alan adları şu IP'lere çözülüyor: " + ", ".join(sorted(set(resolved_info))))
    else:
        if resolved_info:
            link_reasons.append(
                "Alan adları şu IP'lere çözülüyor (USOM'da işaretli değil): " + ", ".join(sorted(set(resolved_info))))
        if ips_seen:
            link_reasons.append("Mesajdaki/çözümlenen IP adresleri USOM kara listesinde işaretli değil: " + ", ".join(
                sorted(set(ips_seen))))

        suspicious_tld_hits = [];
        trusted_hits = []
        for d in domains_seen:
            parts = d.rsplit(".", 2)
            tld2 = parts[-2] + "." + parts[-1] if len(parts) >= 2 else parts[-1]
            simple_tld = parts[-1].lower()
            if (tld2.lower() in TRUSTED_TLDS) or (simple_tld in TRUSTED_TLDS):
                trusted_hits.append(d)
            else:
                if simple_tld in SUSPICIOUS_TLDS or tld2.lower() in SUSPICIOUS_TLDS:
                    suspicious_tld_hits.append(d)

        if trusted_hits:
            link_reasons.append("Güvenilir/kurumsal uzantı tespit edildi: " + ", ".join(sorted(set(trusted_hits))))
        if suspicious_tld_hits:
            link_risk_pct += 50;
            link_reasons.append("Şüpheli/ucuz TLD: " + ", ".join(sorted(set(suspicious_tld_hits))))

        http_count = sum(1 for u in urls if u["type"] == "http_or_known")
        dom_like_count = sum(1 for u in urls if u["type"] == "domain_like")
        if http_count > 0:
            link_risk_pct += 30;
            link_reasons.append(f"{http_count} adet tıklanabilir URL bulundu.")
        if dom_like_count > 0:
            link_risk_pct += 20;
            link_reasons.append(f"{dom_like_count} adet domain benzeri ifade görüldü.")

        if trusted_hits:
            link_risk_pct = max(0.0, link_risk_pct - 40);
            link_reasons.append("Güvenilir TLD var; genel risk düşürüldü.")
        link_risk_pct = min(100.0, link_risk_pct)

    if not link_reasons:
        link_reasons = ["Link bulundu fakat USOM listesinde zararlı değil."]
    return link_risk_pct, link_reasons, True


def combine_risks(content_risk, content_reasons, content_flags,
                  link_risk, link_reasons, link_found):
    """İçerik ve Link risklerini birleştirerek nihai kararı verir."""
    final_reasons = []
    final_reasons.extend(content_reasons)

    phone_info = content_flags.get("phone_info", {})
    if phone_info and phone_info.get("reason"):
        final_reasons.append("Numara analizi: " + phone_info["reason"])

    if link_found:
        final_reasons.extend(link_reasons)

    # Risk Seviyesi Belirleme Mantığı
    if link_risk >= 100:
        final_risk_pct = max(link_risk, 90.0);
        level = "KIRMIZI (USOM Zararlı Uyarısı)";
        color = "#E74C3C"
    elif content_risk >= 70:
        final_risk_pct = max(content_risk, link_risk, 75.0);
        level = "KIRMIZI (Yüksek Risk)";
        color = "#E74C3C"
    else:
        if 30 <= content_risk < 70:
            if not link_found:
                final_risk_pct = max(content_risk, 40.0);
                level = "SARI (Şüpheli / Dikkat)";
                color = "#F1C40F"
            else:
                if link_risk >= 60:
                    final_risk_pct = max(content_risk, link_risk, 75.0);
                    level = "KIRMIZI (Yüksek Risk)";
                    color = "#E74C3C"
                else:
                    final_risk_pct = max(content_risk, 50.0);
                    level = "SARI (Şüpheli / Linke Dikkat)";
                    color = "#F1C40F"
        else:  # content_risk < 30
            if not link_found:
                final_risk_pct = min(content_risk, 25.0);
                level = "YEŞİL (Genelde Güvenli)";
                color = "#2ECC71"
            else:
                if link_risk >= 60:
                    final_risk_pct = max(60.0, link_risk);
                    level = "SARI (Şüpheli Link)";
                    color = "#F1C40F"
                else:
                    final_risk_pct = max(35.0, link_risk, content_risk);
                    level = "SARI (Bilinmeyen Link)";
                    color = "#F1C40F"

    if not final_reasons:
        final_reasons = ["Belirgin tehdit, para talebi, bahis/kumar vaadi veya şüpheli link tespit edilmedi."]

    final_risk_pct = max(0.0, min(100.0, final_risk_pct))
    return final_risk_pct, level, color, final_reasons


# =================================================================
# BÖLÜM 4: FLASK ENTEGRASYONU İÇİN ANA FONKSİYON (run_full_sms_analysis)
# =================================================================

def run_full_sms_analysis(number: str, sms_text: str):
    """
    Flask uygulamasının çağıracağı ana fonksiyon. Tüm analiz adımlarını koordine eder.
    """
    # 1. USOM kara listesini çek
    usom_blocklist = fetch_usom_blocklist()

    # 2. İçerik ve Numara Riskini Analiz Et
    content_risk, content_reasons, content_flags = analyze_text_content_risk(number, sms_text)

    # 3. Link Riskini Analiz Et
    link_risk, link_reasons, link_found = analyze_link_risk(sms_text, usom_blocklist)

    # 4. Tüm Riskleri Birleştir
    final_risk_pct, level, color, final_reasons = combine_risks(
        content_risk, content_reasons, content_flags,
        link_risk, link_reasons, link_found
    )

    # Nihai sonucu Flask'a JSON olarak göndermek için uygun formatta döndür
    return {
        "finalRiskPct": final_risk_pct,
        "level": level,
        "color": color,
        "finalReasons": final_reasons
    }

# =================================================================