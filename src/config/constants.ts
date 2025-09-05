// Configuration constants and schemas
import { z } from "zod";

// API Configuration
export const ONSECURITY_API_BASE = process.env.ONSECURITY_API_BASE;
export const ONSECURITY_API_TOKEN = process.env.ONSECURITY_API_TOKEN;

// Define a schema for advanced filters that can be passed directly to the tool
// NOTE: Date-based filters are prohibited as they cause API errors
export const FilterSchema = z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional();

// Prohibited filter keys that cause API errors
export const PROHIBITED_FILTER_KEYS = [
    'date', 'date-eq', 'date-mte', 'date-lte', 'date-mt', 'date-lt',
    'start_date', 'start_date-eq', 'start_date-mte', 'start_date-lte',
    'end_date', 'end_date-eq', 'end_date-mte', 'end_date-lte',
    'created_at', 'updated_at', 'finished_at'
];

// Task type mappings
export const TASK_TYPE_NAMES: Record<number, string> = {
    1: 'Comment',
    2: 'Review', 
    3: 'Retest Requested',
    4: 'New File',
    5: 'Executive Review',
    6: 'Unknown',
    7: 'New Annotation',
    8: 'Prerequisite'
};