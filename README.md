# EvtxToCsv

Windows Olay Günlüğü (EVTX) dosyalarını CSV formatına dönüştüren Python kütüphanesi.

[![PyPI version](https://badge.fury.io/py/evtxtocsv.svg)](https://badge.fury.io/py/evtxtocsv)
[![Python Versions](https://img.shields.io/pypi/pyversions/evtxtocsv.svg)](https://pypi.org/project/evtxtocsv/)
[![License](https://img.shields.io/pypi/l/evtxtocsv.svg)](https://github.com/MSelcukAkbas/EVTX2CSV/blob/main/LICENSE)

## Özellikler

- Windows Olay Günlüğü (EVTX) dosyalarını CSV formatına dönüştürme
- Kategori bazlı log filtreleme (Sistem, Güvenlik, Uygulama vb.)
- Kritik log dosyalarını otomatik tanımlama ve dönüştürme
- Yönetici izinlerini otomatik yükseltme
- Türkçe arayüz ve hata mesajları

## Kurulum

```bash
pip install evtxtocsv
```

## Gereksinimler

- Python 3.6+
- Windows işletim sistemi
- PowerShell

## Kullanım

### Basit Kullanım

```python
from evtxtocsv import EvtxToCsv

# Tüm logları dönüştürme
converter = EvtxToCsv()
converter.convert_all_logs()
```

### Kategori Bazlı Dönüştürme

```python
from evtxtocsv import EvtxToCsv

# Kütüphaneyi başlat
converter = EvtxToCsv()

# Güvenlik kategorisindeki logları dönüştür
converter.convert_logs_by_category("Security")
```

### Kritik Logları Dönüştürme

```python
from evtxtocsv import EvtxToCsv

# Kütüphaneyi başlat
converter = EvtxToCsv()

# Yalnızca kritik logları dönüştür
converter.convert_critical_logs()
```

### Özel Çıktı Dizini Belirtme

```python
from evtxtocsv import EvtxToCsv

# Özel çıktı dizini belirt
converter = EvtxToCsv(output_directory="C:\\forensics\\logs")

# Dönüştürme işlemini gerçekleştir
converter.convert_all_logs()
```

### Komut Satırı Arayüzü ile Kullanım

```python
import evtxtocsv

# Etkileşimli menü başlatılır
evtxtocsv.easy_usage()
```

## API Referansı

### `EvtxToCsv` Sınıfı

#### Yapıcı

```python
EvtxToCsv(output_directory=None)
```

- **output_directory** (opsiyonel): CSV dosyalarının kaydedileceği dizin. Belirtilmezse "evtx_csv_output" kullanılır.

#### Metodlar

##### `convert_all_logs()`
Sistemdeki tüm log dosyalarını CSV formatına dönüştürür.

##### `convert_critical_logs()`
Kritik log dosyalarını (Sistem, Güvenlik, Uygulama) CSV formatına dönüştürür.

##### `convert_logs_by_category(category)`
Belirtilen kategorideki log dosyalarını CSV formatına dönüştürür.

- **category**: Dönüştürülecek log kategorisi (örn. "System", "Security", "Application" vb.)

##### `get_all_categories()`
Tanımlı tüm log kategorilerini döndürür.

##### `get_logs_by_category(category_name="System")`
Belirtilen kategorideki log dosyalarını döndürür.

- **category_name**: İstenen kategori adı

##### `is_admin()`
Mevcut işlemin yönetici haklarıyla çalışıp çalışmadığını kontrol eder.

## Notlar

- Kütüphane, Windows sistemlerinde yönetici izniyle çalıştırılması gerekebilir.
- İlk kullanımda gerekirse, yönetici izni otomatik olarak istenir.
- Dönüştürme işlemi için PowerShell kullanılır.

## Katkıda Bulunma

Katkıda bulunmak için lütfen bir GitHub "issue" açın veya "pull request" gönderin.

## Lisans

Bu proje MIT Lisansı altında lisanslanmıştır. Daha fazla bilgi için [LICENSE](LICENSE) dosyasına bakın.

## Yazar

[Mustafa Selçuk Akbaş](https://github.com/MSelcukAkbas) - [LinkedIn](https://www.linkedin.com/in/mustafa-selcuk-akbas/) - E-posta: akbasselcuk32@gmail.com

## pypi.org u ziyaret etmeyi unutmayın 

[EVTX2CSV]([https://github.com/MSelcukAkbas/EVTX2CSV](https://pypi.org/project/evtxtocsv/))
