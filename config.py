import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'fb731c467c3df36554f09c6635bc4d8e619d1f96cc3778bbcfa3487dc435a21a'
    CLOUDFLARE_API_BASE_URL = 'https://api.cloudflare.com/client/v4/'
