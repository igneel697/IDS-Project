"""
Alerts API Routes
Endpoints for retrieving alert data from the database.

Author: Pranjal Neupane
Date: April 2026
"""

from flask import Blueprint, jsonify, request
import pymysql
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from config import DB_CONFIG

alerts_bp = Blueprint('alerts', __name__)


def get_db():
    return pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)


@alerts_bp.route('/api/alerts', methods=['GET'])
def get_alerts():
    """
    Get recent alerts.
    Optional query params:
      - limit: number of alerts to return (default 50)
      - severity: filter by severity level
      - attack_type: filter by attack type
    """
    limit       = request.args.get('limit', 50, type=int)
    severity    = request.args.get('severity', None)
    attack_type = request.args.get('attack_type', None)

    try:
        conn   = get_db()
        cursor = conn.cursor()

        query  = "SELECT * FROM alerts"
        params = []
        where  = []

        if severity:
            where.append("severity = %s")
            params.append(severity)
        if attack_type:
            where.append("attack_type = %s")
            params.append(attack_type)
        if where:
            query += " WHERE " + " AND ".join(where)

        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)

        cursor.execute(query, params)
        alerts = cursor.fetchall()

        # Convert datetime to string for JSON
        for alert in alerts:
            if alert.get('timestamp'):
                alert['timestamp'] = str(alert['timestamp'])
            if alert.get('created_at'):
                alert['created_at'] = str(alert['created_at'])

        conn.close()
        return jsonify({
            'success': True,
            'count':   len(alerts),
            'alerts':  alerts
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@alerts_bp.route('/api/alerts/recent', methods=['GET'])
def get_recent_alerts():
    """Get the 10 most recent alerts"""
    try:
        conn   = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10"
        )
        alerts = cursor.fetchall()
        for alert in alerts:
            if alert.get('timestamp'):
                alert['timestamp'] = str(alert['timestamp'])
            if alert.get('created_at'):
                alert['created_at'] = str(alert['created_at'])
        conn.close()
        return jsonify({'success': True, 'alerts': alerts})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@alerts_bp.route('/api/alerts/<int:alert_id>', methods=['GET'])
def get_alert(alert_id):
    """Get a single alert by ID"""
    try:
        conn   = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE alert_id = %s", (alert_id,))
        alert = cursor.fetchone()
        conn.close()
        if not alert:
            return jsonify({'success': False, 'error': 'Alert not found'}), 404
        if alert.get('timestamp'):
            alert['timestamp'] = str(alert['timestamp'])
        return jsonify({'success': True, 'alert': alert})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
