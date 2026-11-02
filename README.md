# AL2100test

**Aplikacja AI typu „wszystko w jednym", napisana w AXCode — deklaratywnym języku aplikacji.**

Jeden plik `.ax` opisuje interfejs, stan, dane, nawigację, bezpieczeństwo, dostępność, tryb
offline i testy. Kompilator zamienia go na aplikację dla iOS, Androida i sieci. Ten projekt
jest dowodem, że model działa na realnym produkcie, a nie na demo składni.

---

## Czym jest AXCode

AXCode nie jest językiem systemowym. Nie zastępuje Swifta, Kotlina ani Rusta. Jest **językiem
warstwy aplikacji**: ekranów, stanu, danych, nawigacji, uprawnień, dostępności i testów.
Kod natywny pozostaje dostępny przez most, ale nie jest wymagany do zbudowania typowego
produktu.

Zamiast trzech–kilkunastu plików HTML, CSS i JavaScript — albo kilku warstw React Native
z osobnym systemem stylów, osobnym modelem komponentów i osobnym mechanizmem zapisu — piszesz
**jeden plik**, który czyta się jak specyfikacja produktu.

### Sześć jednostek programu

| Jednostka | Do czego służy | W tym projekcie |
|---|---|---|
| `app` | nazwa, wersja, platformy, tryb offline | `AL2100test` 1.0.0, iOS + Android + Web |
| `theme` + `style` | tokeny designu i style nazwane | 15 stylów, motyw systemowy/jasny/ciemny |
| `data` + `enum` | modele danych i typy wyliczeniowe | 21 modeli, 13 enumów |
| `store` | trwała warstwa danych | 18 magazynów: `local`, `synced`, `secure`, `encrypted`, `queue` |
| `api` | endpointy z metodą, typem odpowiedzi i obsługą błędu | 3 warstwy API |
| `component` + `screen` + `function` + `test` | widoki, logika i testy | 13 komponentów, 24 ekrany, 251 funkcji, 11 testów |

### Reaktywność bez glue code'u

Zmiana stanu automatycznie aktualizuje interfejs. Nie piszesz ręcznej synchronizacji DOM,
listenerów ani cyklu życia komponentu. `set draft = ""` opróżnia pole w widoku — nic więcej.

### Bezpieczeństwo jest częścią modelu danych

Magazyn deklaruje swoją klasę, a kompilator pilnuje, żeby sekret nie trafił w niezabezpieczone
miejsce. Klucze API providerów leżą w `store providerKeys secure`, tokeny sesji w
`store session secure`, media w `local encrypted`. Nie da się przypadkiem zapisać klucza
w `local` — to błąd kompilacji, nie błąd w produkcji.

### Dostępność jest w semantyce, nie w dodatku

Każdy obraz ma `alt`, każde pole ma `label`, każdy przycisk ikonowy ma `accessibility label`.
Kompilator zgłasza brak jako błąd. W tym projekcie jest **275 etykiet dostępności** i osobny
zestaw testów dostępności uruchamianych przez `ax test a11y`.

---

## Co ten projekt faktycznie zawiera

### `app.ax` — 201 929 znaków, 7368 linii

**24 ekrany:**

| Obszar | Ekrany |
|---|---|
| Wejście | Home, Login, Register, PasswordReset, VerifyEmail, Recovery |
| Konto | Profile, Sessions, Privacy, Notifications |
| Rozmowa | Chat, ChatHistory, ModelPicker |
| Generowanie | ImageStudio, VideoStudio, MusicStudio, Player, Generate |
| Wiedza | Research, Agents |
| System | Providers, Accessibility, Settings, Moderation |

**Trzy warstwy API** opisane w jednym miejscu z metodą, typem odpowiedzi i limitem czasu:
`CloudflareApi` (backend), `PublicResearchApi` (otwarte źródła publiczne) i `Platform` (most
natywny do plików, mowy, wibracji i eksportu).

**Model danych obejmuje cały produkt:** rozmowy i wiadomości z załącznikami i źródłami,
zadania badawcze z listą źródeł i poziomem pewności, agentów z planem i logiem wykonania,
bibliotekę zdjęć, filmów i utworów, konfigurację providerów AI, kolejkę offline z kluczem
idempotencji oraz kody odzyskiwania.

### `worker.ts` — 67 092 znaki, 1491 linii, 36 tras

Backend na Cloudflare Workers: D1 (dane relacyjne), R2 (media), KV (limity i pamięć podręczna),
Queues (zadania w tle).

**Obszar logowania:**

- Rejestracja z walidacją siły hasła i weryfikacją e-maila
- Logowanie hasłem z blokadą po ośmiu nieudanych próbach
- **Logowanie kodem PIN (4–6 cyfr)** powiązanym z urządzeniem — szybkie wejście bez wpisywania hasła
- Reset hasła przez kod, jednorazowe kody odzyskiwania
- Odświeżanie tokenu z rotacją, token dostępu 30 minut, odświeżania 30 dni
- Powiązanie sesji z urządzeniem i zdalne odbieranie dostępu

**Poza tym:** rozmowy i wiadomości, upload mediów, zadania research i agentów przez kolejki,
dziennik użycia providerów, moderacja i zgłaszanie nadużyć, eksport danych i usunięcie konta
(RODO), powiadomienia, panel statusu na `/`.

### `schema.sql` — 17 tabel

`users`, `pin_codes`, `devices`, `sessions`, `email_verifications`, `password_resets`,
`recovery_codes`, `conversations`, `messages`, `media`, `generations`, `provider_usage`,
`research_jobs`, `agent_jobs`, `notifications`, `moderation_reports`, `audit_log`.

---

## Zasady, których ten kod nie łamie

1. **Klucze API nigdy nie opuszczają urządzenia.** Warstwa Bring Your Own AI działa po stronie
   klienta. Backend przyjmuje wyłącznie metadane użycia i odrzuca żądania zawierające pola
   `apiKey`, `api_key`, `key`, `secret`, `token` lub `authorization`.
2. **Treść AI jest zawsze oznaczona.** Każda odpowiedź modelu niesie prefiks `[AI-generated]`
   i widoczną plakietkę w interfejsie.
3. **Każdy research ma źródła.** Odpowiedź bez ani jednego źródła jest jawnie nazwana
   spekulacją, a poziom pewności pokazuje się liczbowo.
4. **Jawo proponuje, człowiek zatwierdza.** Wynik zadania agenta nie jest używany, dopóki
   użytkownik go nie zatwierdzi; poprawka wraca do agenta jako wejście kolejnej iteracji.
5. **Twarda granica dla głosu i wizerunku.** Aplikacja dopuszcza wyłącznie głos syntetyczny.
   Klonowanie głosu realnej osoby i materiały przedstawiające realne osoby w sytuacjach,
   których nie było — są niedostępne.
6. **Tylko legalne źródła.** Wyszukiwanie korzysta z publicznych i udokumentowanych API:
   Wikipedia i Wikidata, Open Library, Internet Archive, OpenAlex, otwarte bazy zdjęć i audio,
   repozytoria open source, dane publiczne. Aplikacja szanuje limity, licencje i regulaminy
   providerów.

---

## Wyszukiwanie wielowarstwowe

Research przechodzi przez dziesięć warstw, z których każda ma własny typ źródła i licencję.
Chodzi o to, żeby odpowiedź nie opierała się na jednym głosie, a użytkownik widział, skąd
pochodzi każde twierdzenie.

| Warstwa | Źródło | Licencja metadanych |
|---|---|---|
| 1 | bezpośrednia odpowiedź modelu | treść AI |
| 2 | publiczny internet | warunki serwisu |
| 3 | Wikipedia, Wikidata, Open Library | CC BY-SA 4.0, CC0 |
| 4 | Internet Archive | zgodnie z licencją zasobu |
| 5 | Pexels, Pixabay | Pexels License, Pixabay Content License |
| 6 | Freesound i otwarte biblioteki audio | zgodnie z licencją zasobu |
| 7 | dokumentacja i repozytoria open source | zgodnie z licencją repozytorium |
| 8 | OpenAlex i publikacje Open Access | CC0 dla metadanych |
| 9 | dane publiczne i API rządowe | domena publiczna |
| 10 | własna baza wiedzy użytkownika | dane użytkownika |

---

## Uruchomienie

### Aplikacja

```bash
ax check          # sprawdzenie typów, dostępności i nawigacji
ax dev            # podgląd z odświeżaniem na żywo
ax run web        # albo: ax run ios / ax run android
ax test           # testy jednostkowe
ax test ui        # testy interfejsu
ax test a11y      # testy dostępności
```

### Backend

```bash
npx wrangler d1 create al2100
npx wrangler r2 bucket create al2100
npx wrangler kv namespace create CACHE
npx wrangler queues create al2100beta
npx wrangler queues create al2100beta-dlq

npx wrangler d1 execute al2100 --remote --file=./schema.sql
npx wrangler secret put JWT_SECRET
npx wrangler deploy
```

Po wdrożeniu `https://<nazwa>.workers.dev/` pokazuje panel ze statusem, a `/health` zwraca
diagnostykę: stan bazy, liczbę tabel, stan pamięci podręcznej.

---

## Zasady wersjonowania AXCode

- **1.x** — stabilny rdzeń języka
- **2.x** — rozszerzenia platformowe i zaawansowane animacje
- **3.x** — edytor wizualny, wtyczki i asystent AI

Zmiana łamiąca składnię wymaga nowej wersji głównej. Kompilator obsługuje co najmniej jedną
wcześniejszą wersję poboczną.

---

## Czego AXCode nie robi

Nie jest językiem systemowym. Nie zastępuje Swifta, Kotlina, Rusta ani C++. Nie odsłania
bezpośrednio DOM, UIKit ani Jetpack Compose. Nie pozwala na dowolne makra ani dynamiczną
ewaluację kodu. Nie gwarantuje identycznego wyglądu piksel w piksel na każdej platformie.
Nie zastępuje backendu. Nie wysyła automatycznie wyników AI bez potwierdzenia. Nie obiecuje
nieograniczonej redukcji kodu.

---

## Licencja i zgodność

Projekt korzysta wyłącznie z legalnych, publicznych i udokumentowanych API. Szanuje limity,
licencje, prawa autorskie i regulaminy providerów. Nie obchodzi zabezpieczeń ani limitów.
Nie pobiera treści chronionych prawem autorskim bez licencji. Nie generuje treści nielegalnych
ani naruszających prawa osób trzecich.

W zakresie prywatności: **brak reklam, brak sprzedaży danych, brak profilowania reklamowego.**
Prawo do eksportu danych i prawo do ich usunięcia są zrealizowane w interfejsie i w backendzie.
Zgodność z RODO, GDPR i CCPA.

---

**AXCode** — jeden plik, cała aplikacja.
