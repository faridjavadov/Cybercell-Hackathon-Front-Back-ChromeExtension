from pydantic import BaseModel
from datetime import datetime
from typing import List
from typing import Optional

class LogCreate(BaseModel):
    url: str
    timestamp: datetime
    type: str
    reason: str

class LogResponse(BaseModel):
    id: int
    url: str
    timestamp: datetime
    type: str
    reason: str
    
    class Config:
        from_attributes = True

class LogStats(BaseModel):
    total_logs: int
    malicious_logs: int
    normal_logs: int
    recent_logs: int

class PaginatedLogs(BaseModel):
    logs: List[LogResponse]
    total: int
    page: int
    per_page: int
    total_pages: int
    has_next: bool
    has_prev: bool

