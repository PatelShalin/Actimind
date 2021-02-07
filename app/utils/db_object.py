from databases import Database
from .const import DB_HOST, DB_NAME, DB_PASSWORD, DB_USER

db = Database(f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}")