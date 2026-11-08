import axios from 'axios';

// Single place where the backend URL is read.
export const BASE_URL = import.meta.env.VITE_API_BASE_URL || '';
export const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';

export const api = axios.create({
  baseURL: BASE_URL,
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
});

export function errorMessage(e) {
  if (e.response) {
    const detail = e.response.data?.message || e.response.data?.detail;
    return `The backend returned ${e.response.status}${detail ? ': ' + detail : ''}.`;
  }
  if (e.request) return 'Cannot reach the backend. Check that it is running and that VITE_API_BASE_URL is correct.';
  return e.message || 'Something went wrong.';
}
