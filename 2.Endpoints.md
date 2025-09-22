# API Endpoints

**Base URL:** `http://localhost:8000`  (port is niet altijd het zelfde, ligt eraan welke ports beschikbaar zijn op PC)

**Auth:** via `Authorization` header met session token (uit `/login`)  
**Content-Type:** JSON waar aangegeven  

---

## Auth & Users  

| Methode | Endpoint   | Auth | Doel | Body | Responses |
|---------|------------|------|------|------|-----------|
| POST    | /register  | ✗    | Nieuwe gebruiker aanmaken | `{ "username": str, "password": str, "name": str, "role"?: "ADMIN"\|"USER" }` | 201 User created · 200 Username taken · 500 bij ontbrekende velden |
| POST    | /login     | ✗    | Inloggen en session token krijgen | `{ "username": str, "password": str }` | 200 OK + token · 400 Missing credentials · 401 Invalid credentials |
| GET     | /logout    | ✓    | Sessie beëindigen | — | 200 Logged out · 400 Invalid session token |

---

## Profile  

| Methode | Endpoint | Auth | Doel | Responses |
|---------|----------|------|------|-----------|
| GET     | /profile | ✓    | Profiel van huidige user ophalen | 200 JSON user (incl. hash!) · 401 Unauthorized |
| PUT     | /profile | ✓    | Profiel bijwerken | 200 Updated · 401 Unauthorized <br> Bug: overschrijft hele `users.json` met één object |

---

## Parking Lots  

| Methode | Endpoint | Auth | Doel | Responses |
|---------|----------|------|------|-----------|
| GET     | /parking-lots | ✗ | Lijst parkeerplaatsen | 200 JSON |
| GET     | /parking-lots/{id} | ✗ | Details parkeerplaats | 200 JSON · 404 Not found |
| POST    | /parking-lots | ADMIN | Nieuwe parkeerplaats toevoegen | 201 Created · 401/403 Unauthorized |
| PUT     | /parking-lots/{id} | ADMIN | Parkeerplaats bijwerken | 200 Modified · 404 Not found |
| DELETE  | /parking-lots/{id} | ADMIN | Parkeerplaats verwijderen | 200 Deleted · 404 Not found |

---

## Sessions  

| Methode | Endpoint | Auth | Doel | Body | Responses |
|---------|----------|------|------|------|-----------|
| POST | /parking-lots/{id}/sessions/start | ✓ | Start sessie | `{ "licenseplate": str }` | 200 Started · 401 Invalid |
| POST | /parking-lots/{id}/sessions/stop  | ✓ | Stop sessie | `{ "licenseplate": str }` | 200 Stopped · 401 Invalid |
| GET  | /parking-lots/{id}/sessions       | ✓ | Sessie-overzicht | — | 200 JSON · 401/403 <br> Bug: `session_user` niet gedefinieerd → 500 |
| GET  | /parking-lots/{id}/sessions/{sid} | ✓ | Specifieke sessie | — | 200 JSON · 403 Access denied |
| DELETE | /parking-lots/{id}/sessions/{sid} | ADMIN | Sessie verwijderen | — | 200 Deleted · 403 Invalid id |

---

## Reservations  

| Methode | Endpoint | Auth | Doel | Responses |
|---------|----------|------|------|-----------|
| POST | /reservations | ✓ | Nieuwe reservering aanmaken | 201 Success · 401 Missing fields · 404 Parking lot not found |
| GET | /reservations/{rid} | ✓ (ADMIN/eigenaar) | Reservering ophalen | 200 JSON · 401/403/404 |
| PUT | /reservations/{rid} | ✓ | Reservering bijwerken | 200 Updated · 401 Missing fields · 404 Not found |
| DELETE | /reservations/{rid} | ✓ (ADMIN/eigenaar) | Reservering verwijderen | 200 Deleted · 401/403/404 <br> Bug: verwijdert eerst en leest daarna → 500 |

---

## Vehicles  

Datastructuur inconsistent: POST gebruikt een lijst, GET/PUT/DELETE verwachten een dictionary. Veel endpoints werken hierdoor niet samen.

| Methode | Endpoint | Auth | Doel | Responses |
|---------|----------|------|------|-----------|
| POST | /vehicles | ✓ | Voertuig toevoegen | 201 Success · 401/404 Errors |
| POST | /vehicles/{id}/entry | ✓ | Entry validatie | 200 Accepted · 401 Invalid |
| GET  | /vehicles | ✓ | Eigen voertuigenlijst | 200 JSON (foutief formaat) |
| GET  | /vehicles/{user} | ADMIN | Voertuigen van gebruiker | 200 JSON · 404 Not found |
| GET  | /vehicles/{id}/reservations | ✓ | Lege lijst of error | 200 [] · 404 Not found |
| GET  | /vehicles/{id}/history | ✓ | Lege lijst of error | 200 [] · 404 Not found |
| PUT  | /vehicles/{id} | ✓ | Voertuig bijwerken | 200 Success · 401 Missing field |
| DELETE | /vehicles/{id} | ✓ | Voertuig verwijderen | 200 Deleted · 403 Vehicle not found |

---

## Payments  

| Methode | Endpoint | Auth | Doel | Responses |
|---------|----------|------|------|-----------|
| POST | /payments | ✓ | Nieuwe betaling | 201 Success · 401 Missing field |
| POST | /payments/refund | ADMIN | Refund uitvoeren | 201 Success · 401/403 Errors |
| PUT | /payments/{transaction} | ✓ | Betaling valideren | 200 Success · 401 Validation failed · 404 Not found |
| GET | /payments | ✓ | Eigen betalingen ophalen | 200 JSON (bijna altijd leeg: filtert op niet-bestaand veld `username`) |
| GET | /payments/{user} | ADMIN | Betalingen gebruiker ophalen | 200 JSON · 403 Access denied <br> Bug: filter foutief veld |

---

## Billing  

| Methode | Endpoint | Auth | Doel | Responses |
|---------|----------|------|------|-----------|
| GET | /billing | ✓ | Kostenoverzicht huidige user | 200 JSON lijst |
| GET | /billing/{user} | ADMIN | Kostenoverzicht gebruiker | 200 JSON lijst · 403 Forbidden |

---

## Overige  

| Methode | Endpoint | Responses |
|---------|----------|-----------|
| GET | /, /index, /index.html | 200 HTML |
| GET | /favicon.ico | 204 No Content |
| * | onbekend pad | 404 Not Found |

---

## Bekende Issues  

- `PUT /profile` overschrijft hele `users.json` met één object  
- `GET /parking-lots/{id}/sessions` → crash door ongedefinieerde `session_user`  
- `DELETE /reservations/{rid}` → verwijdert object en probeert daarna velden te lezen → 500  
- `Vehicles` datastructuur inconsistent (list vs dict) → veel endpoints falen  
- `Payments` filteren op niet-bestaand veld `username` → foutieve/lege resultaten  
- Meerdere endpoints returnen plain text i.p.v. JSON; statuscodes inconsistent  

---

## Testtips

```bash
# Registratie
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"u","password":"p","name":"n"}'

# Login
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"u","password":"p"}'

# Profiel ophalen
curl http://localhost:8000/profile -H "Authorization: <TOKEN>"
```
