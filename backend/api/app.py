"""
Flask API Entry Point
Serves IDS alert data to the React frontend.

Author: Pranjal Neupane
Date: April 2026
"""

from flask import Flask
from flask_cors import CORS
import pymysql
import sys
import os

sys.path.append(os.path.dirname(__file__))
from config import DB_CONFIG, DEBUG, HOST, PORT

app = Flask(__name__)
CORS(app)  # Allow React frontend to call this API


def get_db_connection():
    """Create and return a MySQL database connection"""
    return pymysql.connect(
        **DB_CONFIG,
        cursorclass=pymysql.cursors.DictCursor
    )


# Test route — check if API is running
@app.route('/api/health', methods=['GET'])
def health_check():
    return {
        'status': 'running',
        'message': 'IDS API is online'
    }


# Import and register routes
from routes.alerts import alerts_bp
from routes.stats import stats_bp

app.register_blueprint(alerts_bp)
app.register_blueprint(stats_bp)


if __name__ == '__main__':
    print('=' * 50)
    print('IDS Flask API Starting')
    print(f'Running on http://localhost:{PORT}')
    print('=' * 50)
    app.run(host=HOST, port=PORT, debug=DEBUG)
