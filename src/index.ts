#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import 'dotenv/config';

// OnSecurity API Types
export interface TargetType {
    id: number;
    name: string;
    description: string;
    assessment_name: string;
    assessment_description: string;
    assessment_illustration: string;
    assessment_estimate_multiples: boolean;
    estimate_enabled: boolean;
    order: number;
    target_examples: string[];
    disabled: boolean;
    created_at: string;
    updated_at: string;
}

export interface Target {
    id: number;
    client_id: number;
    target_type_id: number;
    hidden: boolean;
    value: string | null;
    notes: string | null;
    name: string | null;
    created_at: string;
    updated_at: string;
    target_type: {
        object_type: string;
        type: string;
        includes: any[];
        many: boolean;
        name: string;
        result: TargetType;
    };
}


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
    targets?: {
        object_type: string;
        type: string;
        includes: string[];
        many: boolean;
        name: string;
        result: Target[];
    };
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

// Interface for Prerequisite data
export interface PrerequisiteFeature {
    id: number;
    round_id: number;
    name?: string;
    description?: string;
    required?: boolean;
    status?: string;
    created_at?: string;
    updated_at?: string;
}

// Interface for Block data
export interface BlockFeature {
    id: number;
    round_type_id: number;
    name: string;
    executive_description?: string;
    executive_description_html?: string;
    executive_description_md?: string;
    executive_risk?: string;
    executive_risk_html?: string;
    executive_risk_md?: string;
    executive_recommendation?: string;
    executive_recommendation_html?: string;
    executive_recommendation_md?: string;
    description?: string;
    description_html?: string;
    description_md?: string;
    evidence?: string;
    evidence_html?: string;
    evidence_md?: string;
    recommendation?: string;
    recommendation_html?: string;
    recommendation_md?: string;
    remediation_complexity?: number;
    approved: boolean;
    automation_approved: boolean;
    used_count: number;
    ratings?: {
        cvss?: {
            score?: number;
            version?: number[];
            v2?: Record<string, number[]>;
            v3?: Record<string, number[]>;
        };
    };
    cvss?: Record<string, any>;
    created_at: string;
    updated_at: string;
    block_business_risks?: any;
    block_field_variants?: any;
    block_imports?: any;
    block_references?: any;
    block_remediations?: any;
    block_target_types?: any;
    block_variables?: any;
    business_risks?: any;
    remediations?: any;
    revisions?: any;
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

const ONSECURITY_API_BASE = process.env.ONSECURITY_API_BASE;
const ONSECURITY_API_TOKEN = process.env.ONSECURITY_API_TOKEN;

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
  limit?: number,
  search?: string
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
  
  // Add search if provided
  if (search) queryParams.append('search', search);
  
  // Add filters
  Object.entries(filters).forEach(([key, value]) => {
    queryParams.append(`filter[${key}]`, value.toString());
  });
  
  const url = `${ONSECURITY_API_BASE}/${basePath}?${queryParams.toString()}`;
  return await makeOnSecurityRequest<T>(url);
}

// Extract assessment types from targets
function extractAssessmentTypes(round: RoundFeature): string[] {
    if (!round.targets?.result) return [];
    
    const assessmentTypes = new Set<string>();
    
    // Only include assessment types from hidden targets (assessment type placeholders)
    round.targets.result
        .filter(target => target.hidden === true)
        .forEach(target => {
            if (target.target_type?.result?.assessment_name) {
                assessmentTypes.add(target.target_type.result.assessment_name);
            }
        });
    
    return Array.from(assessmentTypes).sort();
}

// Extract actual targets (non-hidden) with their types
function extractActualTargets(round: RoundFeature): { value: string; type: string; notes?: string }[] {
    if (!round.targets?.result) return [];
    
    return round.targets.result
        .filter(target => target.hidden === false && target.value)
        .map(target => ({
            value: target.value!,
            type: target.target_type?.result?.name || 'Unknown',
            notes: target.notes || undefined
        }));
}


// Format Round data
function formatRound(round: RoundFeature): string {
    const assessmentTypes = extractAssessmentTypes(round);
    const actualTargets = extractActualTargets(round);
    
    const result = [
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
    ];
    
    // Add assessment types if available
    if (assessmentTypes.length > 0) {
        result.push(`Assessment Types: ${assessmentTypes.join(', ')}`);
    }
    
    // Add actual targets if available and not too many
    if (actualTargets.length > 0 && actualTargets.length <= 5) {
        result.push(`Targets: ${actualTargets.map(t => `${t.value} (${t.type})`).join(', ')}`);
    } else if (actualTargets.length > 5) {
        result.push(`Targets: ${actualTargets.length} targets configured`);
    }
    
    result.push(`--------------------------------`);
    
    return result.join('\n');
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

// Format Prerequisite data
function formatPrerequisite(prerequisite: PrerequisiteFeature): string {
    return [
        `Prerequisite ID: ${prerequisite.id}`,
        `Round ID: ${prerequisite.round_id}`,
        `Name: ${prerequisite.name || "N/A"}`,
        `Description: ${prerequisite.description || "N/A"}`,
        `Required: ${prerequisite.required !== undefined ? prerequisite.required : "N/A"}`,
        `Status: ${prerequisite.status || "N/A"}`,
        `Created At: ${prerequisite.created_at || "N/A"}`,
        `Updated At: ${prerequisite.updated_at || "N/A"}`,
        `--------------------------------`,
    ].join('\n');
}

// Format Block data
function formatBlock(block: BlockFeature): string {
    return [
        `Block ID: ${block.id}`,
        `Name: ${block.name}`,
        `Round Type ID: ${block.round_type_id}`,
        `Approved: ${block.approved}`,
        `Automation Approved: ${block.automation_approved}`,
        `Used Count: ${block.used_count}`,
        `Remediation Complexity: ${block.remediation_complexity || "N/A"}`,
        `CVSS Score: ${block.ratings?.cvss?.score || block.cvss?.score || "N/A"}`,
        `Executive Description: ${block.executive_description ? block.executive_description.substring(0, 200) + "..." : "N/A"}`,
        `Executive Risk: ${block.executive_risk ? block.executive_risk.substring(0, 200) + "..." : "N/A"}`,
        `Executive Recommendation: ${block.executive_recommendation ? block.executive_recommendation.substring(0, 200) + "..." : "N/A"}`,
        `Description: ${block.description ? block.description.substring(0, 200) + "..." : "N/A"}`,
        `Evidence: ${block.evidence ? block.evidence.substring(0, 200) + "..." : "N/A"}`,
        `Recommendation: ${block.recommendation ? block.recommendation.substring(0, 200) + "..." : "N/A"}`,
        `Created At: ${block.created_at}`,
        `Updated At: ${block.updated_at}`,
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
    "get-rounds",
    "Get all rounds data from OnSecurity from client in a high level summary. When replying, only include the summary, not the raw data and be sure to present the data in a way that is easy to understand for the client. Rounds can be pentest rounds, scan rounds, or radar rounds. When targets are included, this tool will show assessment types (derived from hidden target placeholders) and actual target scope.",
    {
        round_type: z.number().optional().describe("Optional round type to filter rounds, 1 = pentest round, 3 = scan round"),
        sort: z.string().optional().describe("Optional sort parameter in format 'field-direction'. Available values: name-asc, start_date-asc, end_date-asc, authorisation_date-asc, hours_estimate-asc, created_at-asc, updated_at-asc, name-desc, start_date-desc, end_date-desc, authorisation_date-desc, hours_estimate-desc, created_at-desc, updated_at-desc. Default: id-asc"),
        limit: z.number().optional().describe("Optional limit parameter for max results per page (e.g. 15)"),
        page: z.number().optional().describe("Optional page number to fetch (default: 1)"),
        includes: z.string().optional().describe("Optional related data to include as comma-separated values (e.g. 'client,findings,targets,targets.target_type'). Use 'targets,targets.target_type' to see assessment types and target details."),
        fields: z.string().optional().describe("Optional comma-separated list of fields to return (e.g. 'id,name,started'). Use * as wildcard."),
        filters: FilterSchema,
        search: z.string().optional().describe("Search term to find rounds by name of round or name of client")
    },
    async (params) => {
        const filters: Record<string, string | number> = {};
        
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
            params.limit,
            params.search
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
    "get-findings",
    "Get all findings data from OnSecurity from client in a high level summary, only include the summary, not the raw data and be sure to present the data in a way that is easy to understand for the client. You can optionally filter findings by round_id. HOWEVER ONLY USE THIS TOOL WHEN ASKED FOR FINDINGS RELATED TO A CLIENT OR MY FINDINGS, NOT THE BLOCKS TOOL.",
    {
        round_id: z.number().optional().describe("Optional round ID to filter findings"),
        round_type: z.number().optional().describe("Optional round type to filter rounds, 1 = pentest round, 3 = scan round"),
        sort: z.string().optional().describe("Optional sort parameter in format 'field-direction'. Available values: name-asc, round_id-asc, created_at-asc, updated_at-asc, name-desc, round_id-desc, created_at-desc, updated_at-desc. Default: id-asc"),
        limit: z.number().optional().describe("Optional limit parameter for max results per page (e.g. 15)"),
        page: z.number().optional().describe("Optional page number to fetch (default: 1)"),
        includes: z.string().optional().describe("Optional related data to include as comma-separated values (e.g. 'client,round,target_components')"),
        fields: z.string().optional().describe("Optional comma-separated list of fields to return (e.g. 'id,name'). Use * as wildcard."),
        filters: FilterSchema,
        search: z.string().optional().describe("Search term to find findings by name of finding or related content")
    },
    async (params) => {
        const filters: Record<string, string | number> = {};
        
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
            params.limit,
            params.search
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
    "get-notifications",
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
        const filters: Record<string, string | number> = {};
        
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

// Get all prerequisites with pagination and filtering
server.tool(
    "get-prerequisites",
    "Get all prerequisites data from OnSecurity for a specific round. Prerequisites are requirements that need to be fulfilled before a security assessment can begin.",
    {
        round_id: z.number().describe("Required round ID to filter prerequisites"),
        sort: z.string().optional().describe("Optional sort parameter in format 'field-direction'. Available values: name-asc, name-desc, created_at-asc, created_at-desc, updated_at-asc, updated_at-desc. Default: id-asc"),
        limit: z.number().optional().describe("Optional limit parameter for max results per page (e.g. 15)"),
        page: z.number().optional().describe("Optional page number to fetch (default: 1)"),
        fields: z.string().optional().describe("Optional comma-separated list of fields to return (e.g. 'id,name,status'). Use * as wildcard."),
        filters: FilterSchema,
    },
    async (params) => {
        const filters: Record<string, string | number> = {
            'round_id-eq': params.round_id
        };
        
        // Add additional filters if provided
        if (params.filters) {
            Object.entries(params.filters).forEach(([key, value]) => {
                filters[key] = value;
            });
        }
        
        const response = await fetchPage<ApiResponse<PrerequisiteFeature>>(
            'prerequisites', 
            params.page || 1, 
            filters, 
            params.sort, 
            undefined, // includes not mentioned in the docs
            params.fields, 
            params.limit
        );
        
        if (!response) {
            return {
                content: [
                    {
                        type: "text",
                        text: "Error fetching prerequisites data. Please try again."
                    }
                ]
            };
        }
        
        const paginationInfo = formatPaginationInfo(response);
        const formattedPrerequisites = response.result.map(formatPrerequisite);
        
        const responseText = [
            "# Prerequisites Summary",
            "",
            "## Pagination Information",
            paginationInfo,
            "",
            "## Prerequisites Data",
            ...formattedPrerequisites
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

// Get all blocks with pagination and advanced filtering
server.tool(
    "get-blocks",
    "Get all blocks data from OnSecurity. Blocks are reusable security finding templates that can be used across different assessments. They contain standardized vulnerability descriptions, risks, and recommendations. Note that you can get how often a block is used, which is a way to get the most common findings ACROSS ALL CLIENTS ONLY as blocks are the basis of findings across pentests and scans. ",
    {
        round_type_id: z.number().optional().describe("Optional round type ID to filter blocks, 1 = pentest round, 3 = scan round"),
        approved: z.boolean().optional().describe("Optional filter for approved blocks only"),
        automation_approved: z.boolean().optional().describe("Optional filter for automation approved blocks only"),
        sort: z.string().optional().describe("Optional sort parameter in format 'field-direction'. Available values: id-asc, round_type_id-asc, name-asc, approved-asc, used_count-asc, created_at-asc, updated_at-asc, id-desc, round_type_id-desc, name-desc, approved-desc, used_count-desc, created_at-desc, updated_at-desc. Default: id-asc"),
        limit: z.number().optional().describe("Optional limit parameter for max results per page (e.g. 15)"),
        page: z.number().optional().describe("Optional page number to fetch (default: 1)"),
        includes: z.string().optional().describe("Optional related data to include as comma-separated values. Available: block_business_risks, block_field_variants, block_imports, block_references, block_remediations, block_target_types, block_variables, business_risks, remediations, revisions (e.g. 'block_business_risks,block_remediations')"),
        fields: z.string().optional().describe("Optional comma-separated list of fields to return (e.g. 'id,name,approved'). Use * as wildcard."),
        filters: FilterSchema,
        search: z.string().optional().describe("Optional search term to filter blocks by matching text")
    },
    async (params) => {
        const filters: Record<string, string | number> = {};
        
        // Add additional filters if provided
        if (params.filters) {
            Object.entries(params.filters).forEach(([key, value]) => {
                filters[key] = value;
            });
        }
        
        // Add round_type_id filter if provided
        if (params.round_type_id) {
            filters['round_type_id-eq'] = params.round_type_id;
        }
        
        // Add approved filter if provided
        if (params.approved !== undefined) {
            filters['approved-eq'] = params.approved ? 1 : 0;
        }
        
        // Add automation_approved filter if provided
        if (params.automation_approved !== undefined) {
            filters['automation_approved-eq'] = params.automation_approved ? 1 : 0;
        }
        
        const response = await fetchPage<ApiResponse<BlockFeature>>(
            'blocks', 
            params.page || 1, 
            filters, 
            params.sort, 
            params.includes, 
            params.fields, 
            params.limit,
            params.search
        );
        
        if (!response) {
            return {
                content: [
                    {
                        type: "text",
                        text: "Error fetching blocks data. Please try again."
                    }
                ]
            };
        }
        
        const paginationInfo = formatPaginationInfo(response);
        const formattedBlocks = response.result.map(formatBlock);
        
        const responseText = [
            "# Blocks Summary",
            "",
            "## Pagination Information",
            paginationInfo,
            "",
            "## Blocks Data",
            ...formattedBlocks
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
