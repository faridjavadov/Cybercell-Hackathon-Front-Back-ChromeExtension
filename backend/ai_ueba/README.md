# AI UEBA Service

This service provides machine learning-based User and Entity Behavior Analytics (UEBA) for the Inspy Security system.

## Features

- **Anomaly Detection**: Uses Isolation Forest to detect anomalous user behavior patterns
- **Uninstall Prediction**: Predicts likelihood of extension uninstall using Random Forest
- **Real-time Analysis**: FastAPI-based service for real-time behavior analysis
- **Fallback Support**: Graceful degradation when models are not available

## API Endpoints

### Health Check
```
GET /health
```
Returns service health status.

### Simple Analysis
```
POST /analyze-simple
```
Analyzes user behavior logs and returns UEBA predictions.

**Request Body:**
```json
{
  "logs": [
    {
      "id": 1,
      "url": "https://example.com",
      "timestamp": "2025-10-19T07:49:15.000Z",
      "type": "normal",
      "reason": "Page navigation"
    }
  ]
}
```

**Response:**
```json
{
  "anomaly_flag": 0,
  "predicted_uninstall": 0,
  "uninstall_prob": 0.1
}
```

### Detailed Analysis
```
POST /analyze
```
Returns detailed analysis with additional metrics.

## Model Files

The service expects these model files in the working directory:
- `uninstall_predictor.pkl` - Random Forest model for uninstall prediction
- `isolation_forest_model.pkl` - Isolation Forest model for anomaly detection
- `feature_columns.json` - Feature column definitions

If these files are not present, the service will use default values for development.

## Docker Usage

### Build and Run
```bash
# Build the AI service
docker build -t inspy-ai-ueba ./backend/ai_ueba

# Run standalone
docker run -p 8001:8001 inspy-ai-ueba

# Or use docker-compose
docker-compose up ai-ueba
```

### Integration with Main System
The AI service is automatically integrated into the main system via docker-compose. The backend service calls the AI service at `http://ai-ueba:8001/analyze-simple` for UEBA analysis.

## Development

### Local Development
```bash
cd backend/ai_ueba
pip install -r requirements.txt
python ai_api.py
```

### Testing
```bash
# Test the service
python test_ai_service.py
```

## Configuration

The service runs on port 8001 by default. This can be changed by modifying the `uvicorn.run()` call in `ai_api.py`.

## Dependencies

- FastAPI - Web framework
- scikit-learn - Machine learning models
- pandas - Data processing
- joblib - Model serialization
- uvicorn - ASGI server

## Error Handling

The service includes comprehensive error handling:
- Graceful fallback when models are not available
- Timeout handling for external requests
- Detailed error logging
- Safe default values for all predictions
