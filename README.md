# INF2DTeam6
Software construction

## Project Architecture Update

This project has been refactored to improve scalability and performance. The previous blocking `http.server` implementation has been replaced with a modern asynchronous stack:

-   **Web Framework**: FastAPI
-   **ASGI Server**: Uvicorn
-   **Data Storage**: TinyDB (for file-based data) with Redis integration for session management.
-   **Data Validation**: Pydantic models

## Setup and Running the Application

1.  **Clone the repository**:

    ```bash
    git clone <repository_url>
    cd INF2DTeam6
    ```

2.  **Install dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the application**:

    ```bash
    uvicorn MobyPark.api.main:app --host 0.0.0.0 --port 8000 --reload
    ```

    The API will be accessible at `http://localhost:8000`.

4.  **(Optional) Configure Redis for Sessions**:

    To enable Redis for session management, set the `MOBYPARK_REDIS_URL` environment variable:

    ```bash
    export MOBYPARK_REDIS_URL="redis://localhost:6379/0"
    # You can also set session TTL (in seconds)
    export MOBYPARK_SESSION_TTL="3600"
    ```

## API Endpoints

Refer to the `2.Endpoints.md` file for a detailed list of all available API endpoints.
