"""
Flask API Configuration
Author: Pranjal Neupane
Date: April 2026
"""

# Database settings — must match what you set up in Week 1
DB_CONFIG = {
    'host':     'localhost',
    'user':     'pranjal_ids',
    'password': 'Pranjal@2026',
    'database': 'ids_database',
    'charset':  'utf8mb4',
}

# Flask settings
DEBUG = True
HOST  = '0.0.0.0'
PORT  = 5000
