from pydantic import BaseModel, validator
from datetime import datetime
from typing import List, Optional, Union

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

class McpLogCreate(BaseModel):
    timestamp: Union[datetime, str]
    level: str
    message: str
    command: Optional[str] = None
    tool: Optional[str] = None
    target: Optional[str] = None
    
    @validator('timestamp', pre=True)
    def parse_timestamp(cls, v):
        if isinstance(v, str):
            try:
                if ',' in v:
                    v = v.split(',')[0]
                return datetime.strptime(v, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return datetime.now()
        return v

class McpLogResponse(BaseModel):
    id: int
    timestamp: datetime
    level: str
    message: str
    command: Optional[str] = None
    tool: Optional[str] = None
    target: Optional[str] = None
    log_source: Optional[str] = "mcp"
    
    class Config:
        from_attributes = True

class PaginatedMcpLogs(BaseModel):
    logs: List[McpLogResponse]
    total: int
    page: int
    per_page: int
    total_pages: int
    has_next: bool
    has_prev: bool

