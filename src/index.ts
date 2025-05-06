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

// Helper function to add delay between requests
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

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

// Generic pagination function for OnSecurity API
async function fetchAllPages<T, R>(
  basePath: string,
  filters: Record<string, string | number>
): Promise<R[]> {
  // Array to store all results
  const allResults: R[] = [];
  let currentPage = 1;
  let hasMorePages = true;
  
  // Build the filter parameters string
  const filterParams = Object.entries(filters)
    .map(([key, value]) => `filter[${key}]=${value}`)
    .join('&');
  
  // Keep fetching until we run out of pages
  while (hasMorePages) {
    // Construct URL for current page
    const pageUrl = `${ONSECURITY_API_BASE}/${basePath}?${filterParams}&page=${currentPage}`;
    
    // Add delay after first page to avoid rate limiting
    if (currentPage > 1) {
      await delay(3000);
    }
    
    const pageResponse = await makeOnSecurityRequest<T>(pageUrl);
    
    if (!pageResponse) {
      break;
    }
    
    // Cast pageResponse to access page properties
    const typedResponse = pageResponse as unknown as { 
      result: R[]; 
      page: number; 
      total_pages: number;
    };
    
    const pageResults = typedResponse.result || [];
    allResults.push(...pageResults);
    
    // Check if there are more pages by examining total_pages and current page
    if (typedResponse.page < typedResponse.total_pages) {
      currentPage++;
    } else {
      hasMorePages = false;
    }
  }
  
  return allResults;
}

//format Round data
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

//format Finding data
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

//format Notification data
function formatNotification(notification: NotificationFeature): string {
    return [
        `Content: ${notification.heading}`,
        `Created At: ${notification.created_at}`,
        `Updated At: ${notification.updated_at}`,
        `--------------------------------`,
    ].join('\n');
}

// Get all rounds
server.tool(
    "get-all-rounds",
    "Get all rounds data from OnSecurity from client in a high level summary. When replying, only include the summary, not the raw data and be sure to present the data in a way that is easy to understand for the client. Rounds can be pentest rounds, scan rounds, or radar rounds.",
    async () => {
        const filters = { 'client_id-eq': ONSECURITY_CLIENT_ID };
        const allRounds = await fetchAllPages<RoundResponse, RoundFeature>(
            'rounds', 
            filters
        );
        
        const formattedRounds = allRounds.map(formatRound);
        const responseText = `Pagination summary: Retrieved ${allRounds.length} rounds.\n\nHere are the rounds data for the client: ${formattedRounds.join('\n\n')}`;

        return {
            content: [
                {
                    type: "text",
                    text: responseText
                }
            ]
        }
    }
);

// Get all Findings
server.tool(
    "get-all-findings",
    "Get all findings data from OnSecurity from client in a high level summary, only include the summary, not the raw data and be sure to present the data in a way that is easy to understand for the client. You can optionally filter findings by round_id.",
    {
        round_id: z.number().optional().describe("Optional round ID to filter findings")
    },
    async (params) => {
        const filters: Record<string, string | number> = { 'client_id-eq': ONSECURITY_CLIENT_ID };
        
        // Add round_id filter if provided
        if (params.round_id) {
            filters['round_id-eq'] = params.round_id;
        }
        
        const allFindings = await fetchAllPages<FindingResponse, FindingFeature>(
            'findings', 
            filters
        );
        
        const formattedFindings = allFindings.map(formatFinding);
        const responseText = `Pagination summary: Retrieved ${allFindings.length} findings.\n\nHere are the findings data for the client: ${formattedFindings.join('\n\n')}`;

        return {
            content: [
                {
                    type: "text",
                    text: responseText
                }
            ]
        }
    }
);

// Get all notifications
server.tool(
    "get-all-notifications",
    "Get all notifications data from OnSecurity from client in a high level summary, only include the summary, not the raw data and be sure to present the data in a way that is easy to understand for the client.",
    async () => {
        const filters = { 'client_id-eq': ONSECURITY_CLIENT_ID };
        const allNotifications = await fetchAllPages<NotificationResponse, NotificationFeature>(
            'notifications', 
            filters
        );
        
        const formattedNotifications = allNotifications.map(formatNotification);
        const responseText = `Pagination summary: Retrieved ${allNotifications.length} notifications.\n\nHere are the notifications data for the client: ${formattedNotifications.join('\n\n')}`;

        return {
            content: [
                {
                    type: "text",
                    text: responseText
                }
            ]
        }
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