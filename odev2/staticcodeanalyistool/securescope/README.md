# SecureScope IDE — Kurulum Kılavuzu

## Gereksinimler

- **Node.js** v18 veya üzeri → https://nodejs.org
- **Anthropic API Key** → https://console.anthropic.com/api-keys

---

## Kurulum (3 Adım)

### 1. Projeyi Çalıştırın

Terminal (CMD / PowerShell / Terminal) açın, proje klasörüne gidin:

```bash
cd securescope
npm install
```

> İlk kurulum 1-2 dakika sürebilir.

---

### 2. Geliştirme Modunda Başlatın

```bash
npm run dev
```

Uygulama penceresi otomatik açılır.

---

### 3. Masaüstü Uygulaması Olarak Derleyin (Opsiyonel)

**Windows (.exe):**
```bash
npm run build:win
```

**macOS (.dmg):**
```bash
npm run build:mac
```

**Linux (.AppImage):**
```bash
npm run build:linux
```

Derlenen dosya `release/` klasöründe oluşur.

---

## İlk Kullanım

1. Uygulama açıldığında **API Key** penceresi çıkar
2. Anthropic API key'inizi girin (sk-ant-api03-...)
3. **Save & Continue** tıklayın — key yerel olarak kaydedilir

---

## Nasıl Kullanılır

| İşlem | Yöntem |
|-------|--------|
| Dosya aç | `Ctrl+O` veya toolbar "Open File" |
| Klasör aç | `Ctrl+Shift+O` veya "Open Folder" |
| Analiz başlat | `F5` veya "Run Analysis" |
| Yeni dosya | `Ctrl+N` veya sidebar `+` |
| Bulgular | Sağ panel veya alt panel "Findings" |
| Konsol | Alt panel "Console" |

---

## Desteklenen Diller

JavaScript, TypeScript, Python, Go, Java, PHP, Ruby, C#, Rust, C, C++, Kotlin, Swift, SQL, Bash

---

## Sorun Giderme

**`npm install` hatası veriyor:**
- Node.js versiyonunu kontrol edin: `node --version` (v18+ olmalı)

**Uygulama açılmıyor:**
- `npm run dev` çalıştırın ve terminaldeki hatayı kontrol edin

**API hatası:**
- API key'in geçerli olduğunu kontrol edin
- İnternetinizin açık olduğundan emin olun

**"electron not found" hatası:**
```bash
npm install --save-dev electron
```
