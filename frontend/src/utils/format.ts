import { format } from 'date-fns';

/**
 * Safely parses any timestamp (seconds, milliseconds, ISO string) into a Date object.
 * Returns null if invalid or unparseable.
 */
export function safeParseDate(val: any): Date | null {
  if (val === null || val === undefined || val === '') return null;
  
  if (val instanceof Date) {
    return isNaN(val.getTime()) ? null : val;
  }

  // If number or numeric string
  if (typeof val === 'number' || (!isNaN(Number(val)) && typeof val === 'string' && !val.includes('-') && !val.includes('T'))) {
    const num = Number(val);
    if (isNaN(num) || num <= 0) return null;
    // Heuristic: timestamps under 1e11 are in seconds (e.g. 1.7e9), over 1e11 are in milliseconds
    const ms = num < 1e11 ? num * 1000 : num;
    const d = new Date(ms);
    return isNaN(d.getTime()) ? null : d;
  }

  // String parsing (e.g. ISO 8601)
  if (typeof val === 'string') {
    const d = new Date(val);
    return isNaN(d.getTime()) ? null : d;
  }

  return null;
}

/**
 * Safely formats a timestamp to 'HH:mm:ss', never throwing an error.
 */
export function safeFormatTime(val: any, fallback = '--:--:--'): string {
  const d = safeParseDate(val);
  if (!d) return fallback;
  try {
    return format(d, 'HH:mm:ss');
  } catch {
    return fallback;
  }
}

/**
 * Safely formats a timestamp to 'MMM dd, yyyy HH:mm:ss', never throwing an error.
 */
export function safeFormatDateTime(val: any, fallback = 'Unknown Date'): string {
  const d = safeParseDate(val);
  if (!d) return fallback;
  try {
    return format(d, 'MMM dd, yyyy HH:mm:ss');
  } catch {
    return fallback;
  }
}

/**
 * Safely formats a number with toFixed, handling null/undefined/NaN.
 */
export function safeToFixed(val: any, digits = 1, fallback = '0.0'): string {
  const num = Number(val);
  if (isNaN(num) || !isFinite(num)) return fallback;
  return num.toFixed(digits);
}

/**
 * Safely formats a number with toLocaleString, handling null/undefined/NaN.
 */
export function safeLocaleString(val: any, fallback = '0'): string {
  const num = Number(val);
  if (isNaN(num) || !isFinite(num)) return fallback;
  return num.toLocaleString();
}
