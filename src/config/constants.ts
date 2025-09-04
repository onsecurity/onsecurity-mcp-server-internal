// Configuration constants and schemas
import { z } from "zod";

// API Configuration
export const ONSECURITY_API_BASE = process.env.ONSECURITY_API_BASE;
export const ONSECURITY_API_TOKEN = process.env.ONSECURITY_API_TOKEN;

// Define a schema for advanced filters that can be passed directly to the tool
export const FilterSchema = z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).meta({
  override: ({ jsonSchema }) => {
    jsonSchema.additionalProperties = {
      anyOf: [
        { type: 'string' },
        { type: 'number' }, 
        { type: 'boolean' }
      ]
    };
  }
}).optional();

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