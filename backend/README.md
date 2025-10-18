# Inspy Security Backend

A lightweight FastAPI backend for receiving and storing security logs from the Inspy Security Chrome Extension.

## Features

- **RESTful API** for log management
- **SQLite Database** for local storage
- **CORS Support** for Chrome extension integration
- **Statistics Endpoints** for monitoring
- **Clean Data Models** with Pydantic validation

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the server:
```bash
python run_server.py
```

Or using uvicorn directly:
```bash
uvicorn main:app --reload --port 8000
```

## API Endpoints

### Core Endpoints

- `POST /api/logs` - Create a new security log
- `GET /api/logs` - Get all logs (with pagination)
- `GET /api/logs/stats` - Get log statistics
- `GET /api/logs/malicious` - Get malicious logs only
- `DELETE /api/logs/{id}` - Delete specific log
- `DELETE /api/logs` - Clear all logs

### Example Usage

#### Create a Log
```bash
curl -X POST http://localhost:8000/api/logs \
     -H "Content-Type: application/json" \
     -d '{
       "url": "https://example.com/upload",
       "timestamp": "2024-01-01T12:00:00Z",
       "type": "malicious",
       "reason": "Large file upload"
     }'
```

#### Get Statistics
```bash
curl http://localhost:8000/api/logs/stats
```

#### Get All Logs
```bash
curl http://localhost:8000/api/logs
```

## Data Models

### LogCreate
```json
{
  "url": "string",
  "timestamp": "datetime",
  "type": "string",
  "reason": "string"
}
```

### LogResponse
```json
{
  "id": "integer",
  "url": "string",
  "timestamp": "datetime",
  "type": "string",
  "reason": "string"
}
```

### LogStats
```json
{
  "total_logs": "integer",
  "malicious_logs": "integer",
  "normal_logs": "integer",
  "recent_logs": "integer"
}
```

## Database

The backend uses SQLite with the following schema:

```sql
CREATE TABLE logs (
    id INTEGER PRIMARY KEY,
    url VARCHAR NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    type VARCHAR NOT NULL,
    reason VARCHAR NOT NULL
);
```

## Development

### File Structure
```
backend/
├── main.py              # FastAPI application
├── database.py          # SQLAlchemy models and setup
├── models.py            # Pydantic models
├── requirements.txt     # Dependencies
├── run_server.py        # Server runner
└── logs.db             # SQLite database (created automatically)
```

### Testing

Test the API using the interactive docs at:
http://localhost:8000/docs

## Future Enhancements

- **ML Integration** - Add anomaly detection endpoints
- **Authentication** - Secure API endpoints
- **Rate Limiting** - Prevent spam requests
- **Data Export** - CSV/JSON export functionality
- **Real-time Updates** - WebSocket support for live monitoring

