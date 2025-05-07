import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import 'dotenv/config';

// OnSecurity API Types
export interface RoundFeature {
    id: number;
    client_id: number;
    round_type_id: number;
    estimate: {
        time: number;
        period: string;
    };
    start_date: string | null;
    end_date: string | null;
    started: boolean;
    finished: boolean;
    name: string;
    executive_summary_published: boolean;
}

export interface RoundResponse {
    links: {
        self: string;
        first: string;
        next: string | null;
        previous: string | null;
        last: string;
    };
    limit: number;
    sort: null;
    includes: any[];
    total_results: number;
    total_pages: number;
    page: number;
    result: RoundFeature[];
}

export interface FindingFeature {
    id?: number;
    client_id?: number;
    round_id?: number;
    name?: string;
    display_id?: string;
    remediation_complexity?: number;
    executive_description?: string;
    executive_risk?: string;
    executive_recommendation?: string;
    description?: string;
    evidence?: string;
    recommendation?: string;
    cvss?: {
        score?: number;
        severity_label?: string;
        exploitability_label?: string;
        impact_label?: string;
    };
    status?: {
        label?: string;
        description?: string;
    };
    published?: boolean;
}

export interface FindingResponse {
    links: {
        self: string;
        first: string;
        next: string | null;
        previous: string | null;
        last: string;
    };
    limit: number;
    sort: null;
    includes: any[];
    total_results: number;
    total_pages: number;
    page: number;
    result: FindingFeature[];
}

export interface NotificationFeature {
    heading?: string;
    created_at?: string;
    updated_at?: string;
}

export interface NotificationResponse {
    links: {
        self: string;
        first: string;
        next: string | null;
        previous: string | null;
        last: string;
    };
    limit: number;
    sort: null;
    includes: any[];
    total_results: number;
    total_pages: number;
    page: number;
    result: NotificationFeature[];
}

// Define a generic response type for all API responses
export interface ApiResponse<T> {
    links: {
        self: string;
        first: string;
        next: string | null;
        previous: string | null;
        last: string;
    };
    limit: number;
    sort: string | null;
    includes: any[];
    total_results: number;
    total_pages: number;
    page: number;
    result: T[];
}

const ONSECURITY_API_BASE = "https://app.onsecurity.io/api/v2";
const ONSECURITY_API_TOKEN = process.env.ONSECURITY_API_TOKEN;
const ONSECURITY_CLIENT_ID = Number(process.env.ONSECURITY_CLIENT_ID) as number;

// Create server instance
const server = new McpServer({
    name: "onsecurity",
    version: "1.0.0",
    capabilities: {
      resources: {},
      tools: {},
    },
  });

// Helper function for making OnSecurity API requests
export async function makeOnSecurityRequest<T>(url: string): Promise<T | null> {
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

// New function to fetch a single page with all query parameter options
async function fetchPage<T>(
  basePath: string,
  page: number = 1,
  filters: Record<string, string | number> = {},
  sort?: string,
  includes?: string,
  fields?: string,
  limit?: number
): Promise<T | null> {
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
  
  // Add filters
  Object.entries(filters).forEach(([key, value]) => {
    queryParams.append(`filter[${key}]`, value.toString());
  });
  
  const url = `${ONSECURITY_API_BASE}/${basePath}?${queryParams.toString()}`;
  return await makeOnSecurityRequest<T>(url);
}

// Format Round data
function formatRound(round: RoundFeature): string {
    return [
        `Round ID: ${round.id}`,
        `Client ID: ${round.client_id}`,
        `Round Type: ${round.round_type_id === 1 ? "pentest round" : round.round_type_id === 3 ? "scan round" : round.round_type_id}`,
        `Estimated: ${round.estimate.time} ${round.estimate.period}`,
        `Start Date: ${round.start_date || "Unknown"}`,
        `End Date: ${round.end_date || "Unknown"}`,
        `Started: ${round.started}`,
        `Completed: ${round.finished}`,
        `Name: ${round.name}`,
        `Executive Summary Published: ${round.executive_summary_published}`,
        `--------------------------------`,
    ].join('\n');
}

// Format Finding data
function formatFinding(finding: FindingFeature): string {
    return [
        `Finding ID: ${finding.id}`,
        `Display ID: ${finding.display_id}`,
        `Name: ${finding.name}`,
        `Client ID: ${finding.client_id}`,
        `Round ID: ${finding.round_id}`,
        `CVSS Score: ${finding.cvss?.score || "N/A"}`,
        `Severity: ${finding.cvss?.severity_label || "N/A"}`,
        `Status: ${finding.status?.label || "Unknown"} (${finding.status?.description || "No description"})`,
        `Published: ${finding.published}`,
        `Remediation Complexity: ${finding.remediation_complexity || "N/A"}`,
        `Executive Description: ${finding.executive_description || "N/A"}`,
        `Executive Risk: ${finding.executive_risk || "N/A"}`,
        `Executive Recommendation: ${finding.executive_recommendation || "N/A"}`,
        `Description: ${finding.description || "N/A"}`,
        `Evidence: ${finding.evidence || "N/A"}`,
        `Recommendation: ${finding.recommendation || "N/A"}`,
        `--------------------------------`,
    ].join('\n');
}

// Format Notification data
function formatNotification(notification: NotificationFeature): string {
    return [
        `Content: ${notification.heading}`,
        `Created At: ${notification.created_at}`,
        `Updated At: ${notification.updated_at}`,
        `--------------------------------`,
    ].join('\n');
}

// Format pagination info
function formatPaginationInfo<T>(response: ApiResponse<T>): string {
    return [
        `Page ${response.page} of ${response.total_pages}`,
        `Total Results: ${response.total_results}`,
        `Items Per Page: ${response.limit}`,
        `Next Page Available: ${response.links.next ? 'Yes' : 'No'}`,
        `Previous Page Available: ${response.links.previous ? 'Yes' : 'No'}`,
        `--------------------------------`,
    ].join('\n');
}

// Define a schema for advanced filters that can be passed directly to the tool
const FilterSchema = z.record(z.string(), z.union([z.string(), z.number()])).optional()
    .describe("Optional additional filters in format {field: value} or {field-operator: value} where operator can be mt (more than), mte (more than equal), lt (less than), lte (less than equal), eq (equals, default)");

// Get all rounds with pagination and advanced filtering
server.tool(
    "get-all-rounds",
    "Get all rounds data from OnSecurity from client in a high level summary. When replying, only include the summary, not the raw data and be sure to present the data in a way that is easy to understand for the client. Rounds can be pentest rounds, scan rounds, or radar rounds.",
    {
        round_type: z.number().optional().describe("Optional round type to filter rounds, 1 = pentest round, 3 = scan round"),
        sort: z.string().optional().describe("Optional sort parameter (e.g. 'start_date-desc' for newest first)"),
        limit: z.number().optional().describe("Optional limit parameter (e.g. 10 for 10 rounds per page)"),
        page: z.number().optional().describe("Optional page number to fetch (default: 1)"),
        includes: z.string().optional().describe("Optional related data to include (e.g. 'findings' or 'findings.targets')"),
        fields: z.string().optional().describe("Optional comma-separated list of fields to return (e.g. 'id,name,started')"),
        filters: FilterSchema,
    },
    async (params) => {
        const filters: Record<string, string | number> = { 'client_id-eq': ONSECURITY_CLIENT_ID };
        
        // Add additional filters if provided
        if (params.filters) {
            Object.entries(params.filters).forEach(([key, value]) => {
                filters[key] = value;
            });
        }
        
        // Add round_type filter if provided
        if (params.round_type) {
            filters['round_type_id-eq'] = params.round_type;
        }
        
        const response = await fetchPage<ApiResponse<RoundFeature>>(
            'rounds', 
            params.page || 1, 
            filters, 
            params.sort, 
            params.includes, 
            params.fields, 
            params.limit
        );
        
        if (!response) {
            return {
                content: [
                    {
                        type: "text",
                        text: "Error fetching rounds data. Please try again."
                    }
                ]
            };
        }
        
        const paginationInfo = formatPaginationInfo(response);
        const formattedRounds = response.result.map(formatRound);
        
        const responseText = [
            "# Rounds Summary",
            "",
            "## Pagination Information",
            paginationInfo,
            "",
            "## Rounds Data",
            ...formattedRounds
        ].join('\n');

        return {
            content: [
                {
                    type: "text",
                    text: responseText
                }
            ]
        };
    }
);

// Get all Findings with pagination and advanced filtering
server.tool(
    "get-all-findings",
    "Get all findings data from OnSecurity from client in a high level summary, only include the summary, not the raw data and be sure to present the data in a way that is easy to understand for the client. You can optionally filter findings by round_id.",
    {
        round_id: z.number().optional().describe("Optional round ID to filter findings"),
        round_type: z.number().optional().describe("Optional round type to filter rounds, 1 = pentest round, 3 = scan round"),
        sort: z.string().optional().describe("Optional sort parameter (e.g. 'cvss_score-desc' for highest severity first)"),
        limit: z.number().optional().describe("Optional limit parameter (e.g. 10 for 10 findings per page)"),
        page: z.number().optional().describe("Optional page number to fetch (default: 1)"),
        includes: z.string().optional().describe("Optional related data to include (e.g. 'targets' or 'targets.target_components')"),
        fields: z.string().optional().describe("Optional comma-separated list of fields to return (e.g. 'id,name,cvss.score')"),
        filters: FilterSchema,
    },
    async (params) => {
        const filters: Record<string, string | number> = { 'client_id-eq': ONSECURITY_CLIENT_ID };
        
        // Add additional filters if provided
        if (params.filters) {
            Object.entries(params.filters).forEach(([key, value]) => {
                filters[key] = value;
            });
        }
        
        // Add round_id filter if provided
        if (params.round_id) {
            filters['round_id-eq'] = params.round_id;
        }
        
        // Add round_type filter if provided
        if (params.round_type) {
            filters['round_type_id-eq'] = params.round_type;
        }
        
        const response = await fetchPage<ApiResponse<FindingFeature>>(
            'findings', 
            params.page || 1, 
            filters, 
            params.sort, 
            params.includes, 
            params.fields, 
            params.limit
        );
        
        if (!response) {
            return {
                content: [
                    {
                        type: "text",
                        text: "Error fetching findings data. Please try again."
                    }
                ]
            };
        }
        
        const paginationInfo = formatPaginationInfo(response);
        const formattedFindings = response.result.map(formatFinding);
        
        const responseText = [
            "# Findings Summary",
            "",
            "## Pagination Information",
            paginationInfo,
            "",
            "## Findings Data",
            ...formattedFindings
        ].join('\n');

        return {
            content: [
                {
                    type: "text",
                    text: responseText
                }
            ]
        };
    }
);

// Get all notifications with pagination and advanced filtering
server.tool(
    "get-all-notifications",
    "Get all notifications data from OnSecurity from client in a high level summary, only include the summary, not the raw data and be sure to present the data in a way that is easy to understand for the client.",
    {
        sort: z.string().optional().describe("Optional sort parameter (e.g. 'created_at-desc' for newest first)"),
        limit: z.number().optional().describe("Optional limit parameter (e.g. 10 for 10 notifications per page)"),
        page: z.number().optional().describe("Optional page number to fetch (default: 1)"),
        includes: z.string().optional().describe("Optional related data to include"),
        fields: z.string().optional().describe("Optional comma-separated list of fields to return (e.g. 'heading,created_at')"),
        filters: FilterSchema,
    },
    async (params) => {
        const filters: Record<string, string | number> = { 'client_id-eq': ONSECURITY_CLIENT_ID };
        
        // Add additional filters if provided
        if (params.filters) {
            Object.entries(params.filters).forEach(([key, value]) => {
                filters[key] = value;
            });
        }
        
        const response = await fetchPage<ApiResponse<NotificationFeature>>(
            'notifications', 
            params.page || 1, 
            filters, 
            params.sort, 
            params.includes, 
            params.fields, 
            params.limit
        );
        
        if (!response) {
            return {
                content: [
                    {
                        type: "text",
                        text: "Error fetching notifications data. Please try again."
                    }
                ]
            };
        }
        
        const paginationInfo = formatPaginationInfo(response);
        const formattedNotifications = response.result.map(formatNotification);
        
        const responseText = [
            "# Notifications Summary",
            "",
            "## Pagination Information",
            paginationInfo,
            "",
            "## Notifications Data",
            ...formattedNotifications
        ].join('\n');

        return {
            content: [
                {
                    type: "text",
                    text: responseText
                }
            ]
        };
    }
);

// Start the server
async function main() {
    try {
        const transport = new StdioServerTransport();
        await server.connect(transport);
    } catch (error) {
        console.error("Fatal error in main():", error);
        process.exit(1);
    }
}

main();
