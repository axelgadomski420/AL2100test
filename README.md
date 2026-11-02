# AL2100test

Aplikacja AI typu „wszystko w jednym" napisana w AXCode, z backendem na Cloudflare Workers.

## Pliki

| Plik | Co zawiera |
|---|---|
| `app.ax` | Cała aplikacja AXCode: 16 ekranów, modele danych, store'y, API, funkcje i testy |
| `worker.ts` | Backend Cloudflare Workers: auth, urządzenia, rozmowy, media, research, agenci, użycie API, moderacja, prywatność, health check |
| `schema.sql` | Schemat Cloudflare D1 |
| `wrangler.toml` | Konfiguracja Workers, D1, R2, KV, Queues, Durable Objects |

## Uruchomienie aplikacji

```bash
ax check
ax dev
ax run web
ax run ios
ax run android
ax test
ax test ui
ax test a11y
```

## Uruchomienie backendu

```bash
wrangler d1 create al2100test
wrangler r2 bucket create al2100test-media
wrangler kv namespace create CACHE
wrangler queues create al2100test-jobs
wrangler d1 execute al2100test --file=./schema.sql --remote
wrangler secret put JWT_SECRET
wrangler deploy
```

Po `wrangler deploy` wklej identyfikatory z wygenerowanych komend do `wrangler.toml`
(pola `REPLACE_WITH_YOUR_*`) i wdrażaj ponownie.

## Zasady, których trzyma się ten kod

1. **Klucze API nigdy nie opuszczają urządzenia.** Warstwa BYO-AI działa po stronie klienta.
   Backend przyjmuje wyłącznie metadane użycia i odrzuca żądania zawierające pola `apiKey`,
   `key`, `secret`, `token` czy `authorization`.
2. **Treść AI jest oznaczana.** Każda odpowiedź generowana przez model dostaje prefiks
   `[AI-generated]` i widoczną plakietkę w interfejsie.
3. **Każdy research ma źródła.** Odpowiedź bez źródeł jest jawnie oznaczana jako spekulacja.
4. **Zadania agentów czekają na człowieka.** Wynik nie jest używany, dopóki użytkownik go nie zatwierdzi.
5. **Sekrety trafiają tylko do magazynów `secure`.** Tokeny, klucze i dane urządzenia nie są
   zapisywane w magazynach `local`.
6. **Dostępność jest w semantyce.** Każdy obraz ma `alt`, każde pole ma `label`, każdy przycisk
   ikonowy ma `accessibility label`, a każdy gest ma alternatywę przyciskową.

## Czego brakuje i dlaczego

Specyfikacja AXCode definiuje w sekcji 22 wywołania `AI.chat`, `AI.transcribe`, `AI.speak`,
`AI.generateImage` i `AI.generateMusic`. **Nie definiuje `AI.generateVideo`.** Dlatego moduł
filmów (`VideoStudio`) obsługuje parametry, wersjonowanie, napisy, voiceover, muzykę, cięcie,
kadrowanie, eksport MP4/WebM i opis dla osób niewidomych — ale nie zawiera wywołania, którego
język nie ma. Po dodaniu odpowiedniego typu do sekcji 22 wystarczy dopiąć jedno wywołanie.

Generowanie wokalu: aplikacja dopuszcza wyłącznie głos syntetyczny. Klonowanie głosu realnej
osoby wymaga jej wyraźnej, udokumentowanej zgody — bez niej nie jest generowane.

## Licencje i zgodność

Aplikacja korzysta z API publicznych i udokumentowanych. Szanuje limity, licencje i regulaminy
providerów. Nie obchodzi zabezpieczeń, limitów ani uwierzytelniania. Nie pobiera treści
chronionych prawem autorskim bez licencji. Brak reklam, brak sprzedaży danych, brak profilowania
reklamowego. Zgodność z RODO, GDPR i CCPA: prawo do eksportu i prawo do usunięcia danych są
zaimplementowane w ekranie `Privacy` i w endpointach `/privacy/export` oraz `/privacy/erase`.
