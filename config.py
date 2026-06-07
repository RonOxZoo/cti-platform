import os
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
API_SECRET_KEY = os.getenv('API_SECRET_KEY', 'cti-platform-secret-2024')
PORT = int(os.getenv('PORT', 5000))
