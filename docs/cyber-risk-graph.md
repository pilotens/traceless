
# Cyber Risk Graph

Traceless bygger en läsbar, begränsad graf från den senaste lokala kunddatan:

`verksamhetsförmåga → system → tillgång → tjänst → fynd/hot → risk → rekommenderad åtgärd`

Verksamhetskontexten lagras i varje manuell arkitekturversion och omfattar affärsägare,
processer, datakategorier, regelverk, RTO/RPO och en konsekvensprofil. Grafen är ett
besluts- och navigationsunderlag. En grafkant innebär en spårbar relation i aktuell data,
inte bevis för genomförd exploatering eller en fullständigt validerad attackväg.

API: `GET /api/v1/operational/systems/{system_id}/risk-graph`

Svaret innehåller:

- CISO-sammanfattning och säkerhetspoäng,
- verksamhetskontext,
- typade noder och relationer,
- prioriterade rekommenderade åtgärder,
- markering om grafen har begränsats för läsbarhet.
