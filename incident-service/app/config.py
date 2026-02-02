from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    MONGO_URI: str = "mongodb://admin:ChangeMe_Mongo123!@mongodb:27017/?authSource=admin"
    DB_NAME: str = "securelogops"
    SERVICE_NAME: str = "incident-service"

    # Internal (correlation-service -> incident-service)
    INTERNAL_API_KEY: str = "ChangeMe_Internal123!"

    # ✅ RBAC / JWT
    AUTH_ENABLED: bool = True
    JWT_SECRET: str = "ChangeMe_JWT_Secret123!"
    JWT_ALGORITHM: str = "HS256"

settings = Settings()
