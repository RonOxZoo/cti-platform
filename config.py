import os
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
API_SECRET_KEY = os.getenv('API_SECRET_KEY', 'cti-platform-secret-2024')
PORT = int(os.getenv('PORT', 5000))
BROWSER_SERVICE_URL = os.getenv('BROWSER_SERVICE_URL', '')
RENDER_SERVICE_URL = os.getenv('RENDER_SERVICE_URL', '')

# Telegram notifications. Both must be set for notifications to be sent.
# NOTE: the bot token is a secret — never log it or return it in an API response.
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
