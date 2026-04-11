/**
 * API helper — all calls to the Flask backend go through here
 */

import axios from 'axios';

const BASE_URL = 'http://localhost:5000/api';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 10000,
});

export const getAlerts = (params = {}) =>
  api.get('/alerts', { params });

export const getRecentAlerts = () =>
  api.get('/alerts/recent');

export const getAlert = (id) =>
  api.get(`/alerts/${id}`);

export const getSummary = () =>
  api.get('/stats/summary');

export const getTimeline = () =>
  api.get('/stats/timeline');

export default api;
