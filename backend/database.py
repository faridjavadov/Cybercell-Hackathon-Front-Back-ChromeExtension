from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./logs.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Log(Base):
    __tablename__ = "logs"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    type = Column(String, nullable=False)
    reason = Column(String, nullable=False)

class McpLog(Base):
    __tablename__ = "mcp_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False)
    level = Column(String, nullable=False)
    message = Column(String, nullable=False)
    command = Column(String, nullable=True)
    tool = Column(String, nullable=True)
    target = Column(String, nullable=True)
    log_source = Column(String, default="mcp")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
