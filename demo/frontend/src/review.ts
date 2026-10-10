// Production stub: pack review notes are a preview-only QA aid.
// vite.preview.config.ts aliases this module to ./preview/review.ts.
export interface ReviewNote { title: string; body: string; fix?: string }
export const REVIEW: Record<string, ReviewNote[]> = {};
export const WATERMARK_NOTE: ReviewNote | null = null;
export const HAS_REVIEW = false;
