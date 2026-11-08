import axios from 'axios';

// Single place where the backend URL is read.
export const BASE_URL = import.meta.env.VITE_API_BASE_URL || '';
export const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';

export const api = axios.create({
  baseURL: BASE_URL,
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
});

// User-facing wording only. No URLs, status codes or setup hints reach the screen.
export function errorMessage(e) {
  if (e.response) {
    return e.response.status >= 500
      ? 'The scanning service ran into a problem. Please try again shortly.'
      : 'That scan request couldn’t be accepted. Check the address and try again.';
  }
  if (e.request) return 'We couldn’t reach the scanning service. Check your connection and try again.';
  return 'Something went wrong. Please try again.';
}
