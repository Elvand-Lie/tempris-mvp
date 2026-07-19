export function severityClass(value?: string) {
  const severity = (value || 'unknown').toLowerCase();
  if (severity === 'critical') return 'severity critical';
  if (severity === 'high') return 'severity high';
  if (severity === 'medium' || severity === 'moderate') return 'severity medium';
  if (severity === 'low') return 'severity low';
  return 'severity unknown';
}

export function titleCase(value?: string) {
  if (!value) return 'Unavailable';
  return value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function formatDate(value?: string | null) {
  if (!value) return 'Unavailable';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unavailable' : date.toLocaleString();
}
