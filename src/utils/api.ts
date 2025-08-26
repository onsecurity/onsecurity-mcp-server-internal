// API utility functions

// Helper function for making OnSecurity API requests
export async function makeOnSecurityRequest<T>(url: string): Promise<T | null> {
  const ONSECURITY_API_TOKEN = process.env.ONSECURITY_API_TOKEN;
  const headers = {
    "Authorization": `Bearer ${ONSECURITY_API_TOKEN}`,
    "Content-Type": "application/json",
    "Accept": "application/json",
  };

  try {
    const response = await fetch(url, { headers });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return (await response.json()) as T;
  } catch (error) {
    console.error("Error making OnSecurity request:", error);
    return null;
  }
}

// Fetch a single page with all query parameter options
export async function fetchPage<T>(
  basePath: string,
  page: number = 1,
  filters: Record<string, string | number> = {},
  sort?: string,
  includes?: string,
  fields?: string,
  limit?: number,
  search?: string
): Promise<T | null> {
  const ONSECURITY_API_BASE = process.env.ONSECURITY_API_BASE;
  
  // Build query parameters
  const queryParams = new URLSearchParams();
  
  // Add page parameter
  queryParams.append('page', page.toString());
  
  // Add limit if provided
  if (limit) queryParams.append('limit', limit.toString());
  
  // Add sort if provided
  if (sort) queryParams.append('sort', sort);
  
  // Add includes if provided
  if (includes) queryParams.append('include', includes);
  
  // Add fields if provided
  if (fields) queryParams.append('fields', fields);
  
  // Add search if provided
  if (search) queryParams.append('search', search);
  
  // Add filters (convert booleans to 1/0)
  Object.entries(filters).forEach(([key, value]) => {
    const filterValue = typeof value === 'boolean' ? (value ? '1' : '0') : value.toString();
    queryParams.append(`filter[${key}]`, filterValue);
  });
  
  const url = `${ONSECURITY_API_BASE}/${basePath}?${queryParams.toString()}`;
  return await makeOnSecurityRequest<T>(url);
}