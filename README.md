# MobyPark API

Een geavanceerd parkeerbeheersysteem ontwikkeld voor het efficiënt beheren van parkeergarages. Deze robuuste oplossing biedt functionaliteiten voor realtime monitoring van voertuigen, dynamische tariefberekening, reserveringsbeheer en geautomatiseerde facturering.

## Vereisten

Om dit project te runnen zijn er meerdere vereisten:
- Python 3.9 of hoger
- Pip (Python package manager)
- Git (of het complete project folder)

## Installatie

### 1. Repository clonen
```bash
git clone https://github.com/thomassrb/INF2DTeam6/tree/main 
cd MobyPark
```

### 2. Virtuele omgeving opzetten
**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**MacOS / Linux:**
```bash
python3 -m venv venv
source venv\bin\activate
```

### 3. Benodigdheden installeren
```bash
pip install -r requirements.txt
```

### 4. Applicatie starten
```bash
python -m uvicorn MobyPark.api.app:app --reload
```

## Configuratie

Maak een `.env` bestand aan in de hoofdmap met de volgende variabelen:
```
SECRET_KEY=jouw_geheime_sleutel
DATABASE_URL=sqlite:///./mobypark.db
JWT_SECRET=jwt_geheime_sleutel
```

## Eerste keer opstarten

### 1. Start de applicatie
```bash
python -m uvicorn MobyPark.api.app:app --reload
```

### 2. Open de API documentatie
- **Swagger**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### 3. Standaard admin account
- **Gebruikersnaam**: admin
- **Wachtwoord**: admin123

## Probleemoplossingen

### Module not found
**Oplossing**: Zorg ervoor dat de virtuele omgeving geactiveerd is en dat de requirements.txt geïnstalleerd zijn.

### Port is already in usage
**Oplossing**: Stop het proces dat poort 8000 gebruikt, of wijzig de poort met `--port 8001`.

### Database error(s)
**Oplossing**: Controleer of de database bestaat en dat de lees/schrijfrechten wel kloppen.

## Ontwikkelomgeving

Voor ontwikkeling wordt het volgende aanbevolen:
- Visual Studio Code met python-extensie
- Python 3.9+
- SQLite3 editor

## API Documentatie

De API wordt automatisch gedocumenteerd met OpenAPI/Swagger:
- Interactieve API documentatie
- Direct testen van endpoints
- Gedetailleerde request/response voorbeelden

## Testen

De applicatie bevat uitgebreide test coverage:
```bash
# Run alle tests
pytest

# Run met coverage
pytest --cov=MobyPark

# Run specifieke test categorie
pytest tests/unit/
pytest tests/integration/
pytest tests/e2e/
```

## Projectstructuur

```
MobyPark/
├── api/
│   ├── Models/           # Datamodellen (Pydantic)
│   ├── DataAccess/        # Database access layer
│   ├── routes/           # API routes
│   ├── app.py           # Hoofdapplicatie
│   ├── authentication.py # Authenticatie
│   └── session_manager.py # Sessiebeheer
├── tests/
│   ├── unit/            # Unit tests
│   ├── integration/      # Integration tests
│   └── e2e/            # End-to-end tests
└── requirements.txt      # Dependencies
```

## Technische Stack

- **Backend**: FastAPI + Python 3.9+
- **Database**: SQL + JSON
- **Authenticatie**: JWT + Bcrypt
- **Testing**: Pytest
- **Documentation**: OpenAPI/Swagger
- **Version Control**: Git/GitHub

## Licentie

Dit project is ontwikkeld als onderdeel van het Software Construction vak. ~~ Sil Paul
