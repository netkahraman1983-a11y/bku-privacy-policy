# Windows Disk Analizi (salt okunur)

C: ve D: sürücülerini tarar, gereksiz dosyaları sınıflandırır ve masaüstünde
`Disk_Analiz_Raporu` klasörüne Türkçe bir HTML raporu ile CSV dosyaları yazar.

## Çalıştırma

1. `Disk-Analiz.ps1` ve `Calistir.bat` dosyalarını aynı klasöre indirin.
2. `Calistir.bat` dosyasına çift tıklayın (yönetici olarak çalıştırmanız gerekmez).
3. Tarama bitince rapor tarayıcıda kendiliğinden açılır.

Alternatif olarak PowerShell'den:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Disk-Analiz.ps1
```

`-ExecutionPolicy Bypass` yalnızca bu tek çalıştırma için geçerlidir; Windows ayarını değiştirmez.

### Seçenekler

| Parametre | Varsayılan | Açıklama |
|---|---|---|
| `-Suruculer C,D` | `C,D` | Taranacak sürücüler |
| `-EskiIndirmeGun 180` | 180 | Bu kadar gündür değişmeyen indirmeler "eski" sayılır |
| `-EskiProjeGun 365` | 365 | Bu kadar gündür değişmeyen projeler "eski" sayılır |
| `-TekrarHash` | kapalı | Tekrarlanan dosyaları SHA256 ile kesinleştirir (içerik yalnızca yerelde okunur, yavaştır) |
| `-RaporuAcma` | kapalı | Rapor bitince tarayıcıyı açma |

## Güvenlik

- Hiçbir dosyayı **silmez, taşımaz, yeniden adlandırmaz**; program kaldırmaz.
- Kayıt defterine ve Windows ayarlarına dokunmaz; yönetici yetkisi istemez.
- İnternete hiçbir veri göndermez; dosya içeriklerini okumaz (yalnızca `-TekrarHash` verilirse yerelde özet hesaplar).
- Tek yazdığı yer `Masaüstü\Disk_Analiz_Raporu` klasörüdür.
- Erişim izni olmayan klasörler atlanır ve raporun "Erişilemeyenler" sekmesinde listelenir.

## Sınıflandırma

- 🟢 **Temizlenebilir**: Geçici dosyalar ve yeniden oluşturulabilen önbellekler (Temp, tarayıcı önbelleği, Gradle/Pub/npm önbellekleri, Windows Update indirmeleri…).
- 🟡 **Kontrol edilmeli**: Eski indirmeler, kurulum dosyaları, APK/ZIP, yedekler, tekrarlar, çöp kutusu, Windows.old, korumalı projelerdeki `build` klasörleri, eski Android Studio sürümleri, emülatörler.
- 🔴 **Silinmemeli**: Windows ve program dosyaları, AppData, kişisel belgeler, müzik kayıtları, VST/ses kütüphaneleri, Ableton/Flutter/Android projeleri (İSG Asist, BKÜ dahil), kaynak kodlar, Firebase yapılandırmaları, keystore ve diğer kimlik bilgileri.

Emin olunamayan hiçbir öğe 🟢 olarak işaretlenmez.

## Çıktılar

`Disk_Analiz_Raporu.html`, `Disk_Ozeti.csv`, `En_Iyi_10_Oneri.csv`, `En_Buyuk_50_Klasor.csv`,
`En_Buyuk_100_Dosya.csv`, `Klasorler_100MB_Ustu.csv`, `Bulgular_Tumu.csv`, `Kategori_Ozeti.csv`,
`Tekrarlanan_Dosyalar.csv`, `Projeler.csv`, `Korunan_Hassas_Dosyalar.csv`, `Erisilemeyen_Klasorler.csv`
