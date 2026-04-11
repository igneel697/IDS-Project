"""
Statistics API Routes
Endpoints for dashboard summary data.

Author: Pranjal Neupane
Date: April 2026
"""

from flask import Blueprint, jsonify
import pymysql
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from config import DB_CONFIG

stats_bp = Blueprint('stats', __name__)


def get_db():
    return pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)


@stats_bp.route('/api/stats/summary', methods=['GET'])
def get_summary():
    """
    Get dashboard summary:
    - Total alerts
    - Alerts by severity
    - Alerts by attack type
    - Alerts by detection method
    """
    try:
        conn   = get_db()
        cursor = conn.cursor()

        # Total alerts
        cursor.execute("SELECT COUNT(*) as total FROM alerts")
        total = cursor.fetchone()['total']

        # By severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM alerts
            GROUP BY severity
            ORDER BY count DESC
        """)
        by_severity = cursor.fetchall()

        # By attack type
        cursor.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM alerts
            GROUP BY attack_type
            ORDER BY count DESC
        """)
        by_attack = cursor.fetchall()

        # By detection method
        cursor.execute("""
            SELECT detection_method, COUNT(*) as count
            FROM alerts
            GROUP BY detection_method
        """)
        by_method = cursor.fetchall()

        # Average risk score
        cursor.execute("SELECT AVG(risk_score) as avg_score FROM alerts")
        avg_score = cursor.fetchone()['avg_score']

        conn.close()
        return jsonify({
            'success':     True,
            'total_alerts': total,
            'by_severity': by_severity,
            'by_attack':   by_attack,
            'by_method':   by_method,
            'avg_risk_score': round(float(avg_score), 1) if avg_score else 0
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@stats_bp.route('/api/stats/timeline', methods=['GET'])
def get_timeline():
    """Get alert counts grouped by hour for the last 24 hours"""
    try:
        conn   = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00') as hour,
                COUNT(*) as count
            FROM alerts
            WHERE timestamp >= NOW() - INTERVAL 24 HOUR
            GROUP BY hour
            ORDER BY hour ASC
        """)
        timeline = cursor.fetchall()
        for row in timeline:
            row['hour'] = str(row['hour'])
        conn.close()
        return jsonify({'success': True, 'timeline': timeline})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
