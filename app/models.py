from sqlalchemy import Column, Integer, BigInteger, String, Boolean
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=True)  # nullable for Telegram-only users
    hashed_password = Column(String, nullable=True)  # nullable for social login
    avatar = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    google_id = Column(String, nullable=True, unique=True, index=True)
    telegram_id = Column(BigInteger, nullable=True, unique=True, index=True)
    telegram_username = Column(String, nullable=True)
