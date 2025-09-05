#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import 'dotenv/config';

// Import organized modules
import type { ApiResponse, RoundFeature, FindingFeature, NotificationFeature, PrerequisiteFeature, BlockFeature, PlatformTask, PlatformPod, PlatformUser, RoundAutomationFeature, RoundArtifactFeature, ClientReportTemplateFeature, PlatformTimeLog } from './types/index.js';
import { 
    fetchPage, 
    makeOnSecurityRequest, 
    formatRound, 
    formatFinding, 
    formatNotification, 
    formatPrerequisite, 
    formatBlock, 
    formatPaginationInfo,
    extractAssessmentTypes,
    extractActualTargets,
    extractTeamInfo,
    extractTimeData
} from './utils/index.js';
import { FilterSchema, TASK_TYPE_NAMES } from './config/constants.js';

// Get environment variables
const ONSECURITY_API_BASE = process.env.ONSECURITY_API_BASE;
const ONSECURITY_API_TOKEN = process.env.ONSECURITY_API_TOKEN;

// Export types for backward compatibility (temporary)
export type * from './types/index.js';

// Initialize MCP server
const server = new McpServer(
    {
        name: "onsec-mcp-server",
        version: "1.0.0",
    },
    {
        capabilities: {
            tools: {},
        },
    }
);

// MCP Tools - All tools are defined inline for maintainability

// Get all rounds with pagination and advanced filtering
server.tool(
    "get-rounds",
    "Get all rounds data from OnSecurity from client in a high level summary. When replying, only include the summary, not the raw data and be sure to present the data in a way that is easy to understand for the client. Defaults to pentest rounds only (round_type_id=1). To include scan rounds or radar rounds, specify round_type parameter. When targets are included, this tool will show assessment types (derived from hidden target placeholders) and actual target scope.",
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
                filters[key] = typeof value === 'boolean' ? (value ? 1 : 0) : value as string | number;
            });
        }
        
        // Add round_type filter - default to pentest rounds (1) if not specified
        if (params.round_type) {
            filters['round_type_id-eq'] = params.round_type;
        } else {
            filters['round_type_id-eq'] = 1; // Default to pentest rounds only
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
    "Get all findings data from OnSecurity from client in a high level summary, only include the summary, not the raw data and be sure to present the data in a way that is easy to understand for the client. Defaults to pentest rounds only (round_type_id=1). You can optionally filter findings by round_id. HOWEVER ONLY USE THIS TOOL WHEN ASKED FOR FINDINGS RELATED TO A CLIENT OR MY FINDINGS, NOT THE BLOCKS TOOL.",
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
                filters[key] = typeof value === 'boolean' ? (value ? 1 : 0) : value as string | number;
            });
        }
        
        // Add round_id filter if provided
        if (params.round_id) {
            filters['round_id-eq'] = params.round_id;
        }
        
        // Add round_type filter - default to pentest rounds (1) if not specified
        if (params.round_type) {
            filters['round_type_id-eq'] = params.round_type;
        } else {
            filters['round_type_id-eq'] = 1; // Default to pentest rounds only
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

// Additional MCP tools continue here

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
                filters[key] = typeof value === 'boolean' ? (value ? 1 : 0) : value as string | number;
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
                filters[key] = typeof value === 'boolean' ? (value ? 1 : 0) : value as string | number;
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
                filters[key] = typeof value === 'boolean' ? (value ? 1 : 0) : value as string | number;
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

// ==================== NEW MCP TOOLS ====================

// 1. Get Round Automations - Track automation status
server.tool(
    "get-round-automations",
    "Get automation execution data for rounds, including status and failures",
    {
        round_id: z.number().optional().describe("Optional round ID to filter automations"),
        status: z.enum(['pending', 'running', 'completed', 'failed']).optional().describe("Filter by automation status"),
        automation_type: z.string().optional().describe("Filter by automation type"),
        sort: z.string().optional().describe("Sort parameter (e.g., 'created_at-desc')"),
        limit: z.number().optional().describe("Max results per page"),
        page: z.number().optional().describe("Page number"),
        filters: FilterSchema
    },
    async (params) => {
        const filters: Record<string, string | number> = {};
        
        if (params.round_id) {
            filters['round_id-eq'] = params.round_id;
        }
        
        if (params.status) {
            filters['status-eq'] = params.status;
        }
        
        if (params.automation_type) {
            filters['automation_type-eq'] = params.automation_type;
        }
        
        if (params.filters) {
            Object.entries(params.filters).forEach(([key, value]) => {
                filters[key] = typeof value === 'boolean' ? (value ? 1 : 0) : value;
            });
        }
        
        const response = await fetchPage<ApiResponse<RoundAutomationFeature>>(
            'round-automations',
            params.page || 1,
            filters,
            params.sort,
            undefined,
            '*',
            params.limit
        );
        
        if (!response) {
            return {
                content: [{
                    type: "text",
                    text: "Error fetching automation data."
                }]
            };
        }
        
        // Format automation status summary
        const statusCounts = response.result.reduce((acc: any, auto) => {
            acc[auto.status || 'unknown'] = (acc[auto.status || 'unknown'] || 0) + 1;
            return acc;
        }, {});
        
        const failedAutomations = response.result.filter(a => a.status === 'failed');
        
        const responseText = [
            "# Round Automations Summary",
            "",
            "## Status Overview",
            `- Pending: ${statusCounts.pending || 0}`,
            `- Running: ${statusCounts.running || 0}`,
            `- Completed: ${statusCounts.completed || 0}`,
            `- Failed: ${statusCounts.failed || 0}`,
            "",
            failedAutomations.length > 0 ? "## Failed Automations (Require Attention)" : "",
            ...failedAutomations.map(a => [
                `### Automation ${a.id} (Round ${a.round_id})`,
                `Type: ${a.automation_type || 'Unknown'}`,
                `Failed at: ${a.completed_at || 'Unknown'}`,
                `Error: ${a.error_message || 'No error message'}`,
                "---"
            ].join('\n')),
            "",
            `Total Automations: ${response.total_results}`,
            `Page ${response.page} of ${response.total_pages}`
        ].filter(Boolean).join('\n');
        
        return {
            content: [{
                type: "text",
                text: responseText
            }]
        };
    }
);

// 2. Get Round Artifacts - Manage assessment files
server.tool(
    "get-round-artifacts",
    "Get artifacts/files associated with rounds",
    {
        round_id: z.number().optional().describe("Optional round ID to filter artifacts"),
        file_type: z.string().optional().describe("Filter by file type"),
        sort: z.string().optional().describe("Sort parameter"),
        limit: z.number().optional().describe("Max results per page"),
        page: z.number().optional().describe("Page number"),
        filters: FilterSchema
    },
    async (params) => {
        const filters: Record<string, string | number> = {};
        
        if (params.round_id) {
            filters['round_id-eq'] = params.round_id;
        }
        
        if (params.file_type) {
            filters['file_type-eq'] = params.file_type;
        }
        
        if (params.filters) {
            Object.entries(params.filters).forEach(([key, value]) => {
                filters[key] = typeof value === 'boolean' ? (value ? 1 : 0) : value;
            });
        }
        
        const response = await fetchPage<ApiResponse<RoundArtifactFeature>>(
            'round-artifacts',
            params.page || 1,
            filters,
            params.sort,
            undefined,
            '*',
            params.limit
        );
        
        if (!response) {
            return {
                content: [{
                    type: "text",
                    text: "Error fetching artifacts data."
                }]
            };
        }
        
        // Group artifacts by round
        const artifactsByRound = response.result.reduce((acc: any, artifact) => {
            if (!acc[artifact.round_id]) {
                acc[artifact.round_id] = [];
            }
            acc[artifact.round_id].push(artifact);
            return acc;
        }, {});
        
        const responseText = [
            "# Round Artifacts Summary",
            "",
            ...Object.entries(artifactsByRound).map(([roundId, artifacts]: any) => [
                `## Round ${roundId}`,
                `Total Files: ${artifacts.length}`,
                "",
                ...artifacts.map((a: RoundArtifactFeature) => 
                    `- ${a.filename || 'Unnamed'} (${a.file_type || 'Unknown type'}, ${
                        a.file_size ? `${(a.file_size / 1024).toFixed(2)} KB` : 'Size unknown'
                    })`
                ),
                ""
            ].join('\n')),
            `Total Artifacts: ${response.total_results}`,
            `Page ${response.page} of ${response.total_pages}`
        ].join('\n');
        
        return {
            content: [{
                type: "text",
                text: responseText
            }]
        };
    }
);

// 3. Get Enhanced Round Summary with Time Tracking and Team Info
server.tool(
    "get-round-summary",
    "Get comprehensive round summary including time tracking, team assignments, and progress",
    {
        round_id: z.number().describe("Round ID to get summary for"),
        include_findings: z.boolean().optional().default(true).describe("Include findings summary"),
        include_time_tracking: z.boolean().optional().default(true).describe("Include time tracking data"),
        include_team: z.boolean().optional().default(true).describe("Include team information"),
        include_prerequisites: z.boolean().optional().default(true).describe("Include prerequisites status")
    },
    async (params) => {
        // Fetch round with all relevant includes
        const includes = [
            'client',
            'findings',
            'prerequisites',
            'targets',
            'targets.target_type',
            params.include_time_tracking ? 'time_logs' : null,
            params.include_team ? 'round_team_users,team_leader_user' : null
        ].filter(Boolean).join(',');
        
        const url = `${ONSECURITY_API_BASE}/rounds/${params.round_id}?include=${includes}`;
        const round = await makeOnSecurityRequest<any>(url);
        
        if (!round) {
            return {
                content: [{
                    type: "text",
                    text: "Error fetching round summary."
                }]
            };
        }
        
        // Extract various data points
        const teamInfo = extractTeamInfo(round);
        const timeData = extractTimeData(round);
        const assessmentTypes = extractAssessmentTypes(round);
        const targets = extractActualTargets(round);
        
        // Calculate findings summary
        const findingsSummary = round.findings?.result ? {
            total: round.findings.result.length,
            critical: round.findings.result.filter((f: any) => f.cvss?.score >= 9).length,
            high: round.findings.result.filter((f: any) => f.cvss?.score >= 7 && f.cvss?.score < 9).length,
            medium: round.findings.result.filter((f: any) => f.cvss?.score >= 4 && f.cvss?.score < 7).length,
            low: round.findings.result.filter((f: any) => f.cvss?.score < 4).length
        } : null;
        
        // Calculate prerequisites status
        const prerequisitesSummary = round.prerequisites?.result ? {
            total: round.prerequisites.result.length,
            completed: round.prerequisites.result.filter((p: any) => p.status === 'completed').length,
            pending: round.prerequisites.result.filter((p: any) => p.status !== 'completed').length,
            required_pending: round.prerequisites.result.filter((p: any) => 
                p.required && p.status !== 'completed'
            ).length
        } : null;
        
        const responseText = [
            `# Round Summary: ${round.name}`,
            "",
            "## Basic Information",
            `- **Round ID:** ${round.id}`,
            `- **Client:** ${round.client?.result?.name || 'Unknown'}`,
            `- **Type:** ${round.round_type_id === 1 ? "Penetration Test" : round.round_type_id === 3 ? "Vulnerability Scan" : "Other"}`,
            `- **Pod:** ${round.pod_id ? `Pod ${round.pod_id}` : 'Not assigned'}`,
            `- **Status:** ${round.started ? (round.finished ? "✅ Completed" : "🔄 In Progress") : "📅 Scheduled"}`,
            `- **Dates:** ${round.start_date || 'TBD'} to ${round.end_date || 'TBD'}`,
            `- **Executive Summary:** ${round.executive_summary_published ? "✅ Published" : "❌ Not Published"}`,
            "",
            assessmentTypes.length > 0 ? "## Assessment Types" : "",
            ...assessmentTypes.map(type => `- ${type}`),
            "",
            targets.length > 0 ? "## Target Scope" : "",
            ...targets.slice(0, 10).map(t => `- ${t.value} (${t.type})`),
            targets.length > 10 ? `... and ${targets.length - 10} more targets` : "",
            "",
            params.include_team && teamInfo ? "## Team Assignment" : "",
            teamInfo.pod ? `- **Pod:** ${teamInfo.pod}` : "",
            teamInfo.team_leader ? `- **Team Leader:** ${teamInfo.team_leader}` : "",
            teamInfo.team_members ? `- **Team Members:** ${teamInfo.team_members.join(', ')}` : "",
            "",
            params.include_time_tracking ? "## Time Tracking" : "",
            params.include_time_tracking ? `- **Estimated:** ${timeData.estimated} hours` : "",
            params.include_time_tracking ? `- **Logged:** ${timeData.logged} hours` : "",
            params.include_time_tracking ? `- **Remaining:** ${timeData.remaining} hours` : "",
            params.include_time_tracking && timeData.estimated > 0 ? 
                `- **Progress:** ${((timeData.logged / timeData.estimated) * 100).toFixed(1)}%` : "",
            "",
            params.include_findings && findingsSummary ? "## Findings Summary" : "",
            params.include_findings && findingsSummary ? `- **Total Findings:** ${findingsSummary.total}` : "",
            params.include_findings && findingsSummary ? `- **Critical:** ${findingsSummary.critical}` : "",
            params.include_findings && findingsSummary ? `- **High:** ${findingsSummary.high}` : "",
            params.include_findings && findingsSummary ? `- **Medium:** ${findingsSummary.medium}` : "",
            params.include_findings && findingsSummary ? `- **Low:** ${findingsSummary.low}` : "",
            "",
            params.include_prerequisites && prerequisitesSummary ? "## Prerequisites Status" : "",
            params.include_prerequisites && prerequisitesSummary ? 
                `- **Total:** ${prerequisitesSummary.total}` : "",
            params.include_prerequisites && prerequisitesSummary ? 
                `- **Completed:** ${prerequisitesSummary.completed}` : "",
            params.include_prerequisites && prerequisitesSummary ? 
                `- **Pending:** ${prerequisitesSummary.pending}` : "",
            params.include_prerequisites && prerequisitesSummary && prerequisitesSummary.required_pending > 0 ? 
                `- **⚠️ Required Prerequisites Pending:** ${prerequisitesSummary.required_pending}` : "",
        ].filter(Boolean).join('\n');
        
        return {
            content: [{
                type: "text",
                text: responseText
            }]
        };
    }
);

// 5. Get Vulnerability Trends Analysis
server.tool(
    "get-vulnerability-trends",
    "Analyze vulnerability trends using block usage data across all assessments",
    {
        round_type_id: z.number().optional().describe("Filter by round type (1=pentest, 3=scan)"),
        min_usage_count: z.number().optional().default(5).describe("Minimum usage count to include"),
        limit: z.number().optional().default(20).describe("Number of top vulnerabilities to show"),
        include_remediation: z.boolean().optional().default(true).describe("Include remediation complexity")
    },
    async (params) => {
        const filters: Record<string, string | number> = {};
        
        if (params.round_type_id) {
            filters['round_type_id-eq'] = params.round_type_id;
        }
        
        filters['used_count-mte'] = params.min_usage_count || 5;
        
        const response = await fetchPage<ApiResponse<BlockFeature>>(
            'blocks',
            1,
            filters,
            'used_count-desc', // Sort by most used
            params.include_remediation ? 'block_remediations' : undefined,
            'id,name,used_count,remediation_complexity,ratings',
            params.limit
        );
        
        if (!response) {
            return {
                content: [{
                    type: "text",
                    text: "Error fetching vulnerability trends."
                }]
            };
        }
        
        // Calculate severity distribution
        const severityDist = response.result.reduce((acc: any, block) => {
            const score = block.ratings?.cvss?.score || block.cvss?.score || 0;
            let severity = 'Unknown';
            if (score >= 9) severity = 'Critical';
            else if (score >= 7) severity = 'High';
            else if (score >= 4) severity = 'Medium';
            else if (score > 0) severity = 'Low';
            
            acc[severity] = (acc[severity] || 0) + block.used_count;
            return acc;
        }, {});
        
        const totalOccurrences = Object.values(severityDist).reduce((a, b) => (a as number) + (b as number), 0);
        
        const responseText = [
            "# Vulnerability Trends Analysis",
            "",
            "## Top Recurring Vulnerabilities",
            "These are the most frequently identified vulnerabilities across all assessments:",
            "",
            ...response.result.slice(0, 10).map((block, index) => {
                const score = block.ratings?.cvss?.score || block.cvss?.score || 0;
                const severity = score >= 9 ? "🔴 CRITICAL" : 
                               score >= 7 ? "🟠 HIGH" : 
                               score >= 4 ? "🟡 MEDIUM" : 
                               score > 0 ? "🟢 LOW" : "⚪ UNKNOWN";
                
                return [
                    `### ${index + 1}. ${block.name}`,
                    `- **Occurrences:** ${block.used_count} times`,
                    `- **Severity:** ${severity} (CVSS: ${score || 'N/A'})`,
                    params.include_remediation ? 
                        `- **Remediation Complexity:** ${block.remediation_complexity || 'Not specified'}` : "",
                    "---"
                ].filter(Boolean).join('\n');
            }),
            "",
            "## Severity Distribution",
            `Total Vulnerability Occurrences: ${totalOccurrences}`,
            "",
            ...Object.entries(severityDist)
                .sort(([,a]: any, [,b]: any) => b - a)
                .map(([severity, count]: any) => 
                    `- **${severity}:** ${count} occurrences (${((count as number)/(totalOccurrences as number)*100).toFixed(1)}%)`
                ),
            "",
            "## Insights",
            `- Most common vulnerability: ${response.result[0]?.name || 'N/A'} (${response.result[0]?.used_count || 0} occurrences)`,
            `- Average occurrences per vulnerability: ${(response.result.reduce((sum, b) => sum + b.used_count, 0) / response.result.length).toFixed(1)}`,
            `- Vulnerabilities analyzed: ${response.total_results}`
        ].join('\n');
        
        return {
            content: [{
                type: "text",
                text: responseText
            }]
        };
    }
);

// 6. Get Client Report Templates
server.tool(
    "get-report-templates",
    "Get available report templates for clients",
    {
        client_id: z.number().optional().describe("Optional client ID to filter templates"),
        template_type: z.string().optional().describe("Filter by template type"),
        is_default: z.boolean().optional().describe("Filter for default templates only"),
        sort: z.string().optional().describe("Sort parameter"),
        limit: z.number().optional().describe("Max results per page"),
        page: z.number().optional().describe("Page number")
    },
    async (params) => {
        const filters: Record<string, string | number> = {};
        
        if (params.client_id) {
            filters['client_id-eq'] = params.client_id;
        }
        
        if (params.template_type) {
            filters['template_type-eq'] = params.template_type;
        }
        
        if (params.is_default !== undefined) {
            filters['is_default-eq'] = params.is_default ? 1 : 0;
        }
        
        const response = await fetchPage<ApiResponse<ClientReportTemplateFeature>>(
            'client-report-templates',
            params.page || 1,
            filters,
            params.sort,
            'client',
            '*',
            params.limit
        );
        
        if (!response) {
            return {
                content: [{
                    type: "text",
                    text: "Error fetching report templates."
                }]
            };
        }
        
        // Group templates by type
        const templatesByType = response.result.reduce((acc: any, template) => {
            const type = template.template_type || 'General';
            if (!acc[type]) acc[type] = [];
            acc[type].push(template);
            return acc;
        }, {});
        
        const responseText = [
            "# Report Templates",
            "",
            ...Object.entries(templatesByType).map(([type, templates]: any) => [
                `## ${type} Templates`,
                ...templates.map((t: ClientReportTemplateFeature) => 
                    `- **${t.template_name}** ${t.is_default ? '(Default)' : ''} - Client: ${t.client_id || 'Global'}`
                ),
                ""
            ].flat()),
            `Total Templates: ${response.total_results}`,
            `Page ${response.page} of ${response.total_pages}`
        ].join('\n');
        
        return {
            content: [{
                type: "text",
                text: responseText
            }]
        };
    }
);

// 7. Get Platform Pods (Team Structure)
server.tool(
    "get-platform-pods",
    "Get platform pods (teams) from OnSecurity API. Shows pod structure with member names, roles, and team composition. Use this to understand which team members are in each pod.",
    {
        includes: z.string().optional().describe("Include related data: 'pod_users,pod_users.user' for member details"),
        limit: z.number().optional().describe("Max results per page (default: all pods)"),
        page: z.number().optional().describe("Page number (default: 1)")
    },
    async (params) => {
        const response = await fetchPage<ApiResponse<PlatformPod>>(
            'platform/pods',
            params.page || 1,
            {},
            'id-asc',
            params.includes || 'pod_users,pod_users.user',
            '*',
            params.limit || 50
        );
        
        if (!response) {
            return {
                content: [{
                    type: "text",
                    text: "Error fetching platform pods."
                }]
            };
        }

        const responseText = [
            "# Platform Pods (Teams)",
            `Found ${response.total_results} pods`,
            "",
            ...response.result.map(pod => {
                const members = pod.pod_users?.result || [];
                const memberList = members.map(member => {
                    const user = member.user?.result;
                    const name = user ? `${user.forename} ${user.surname}` : `User ${member.user_id}`;
                    const title = user?.job_title ? ` (${user.job_title})` : '';
                    const role = member.role ? ` - ${member.role}` : '';
                    return `  - ${name}${title}${role}`;
                }).join('\n');
                
                return [
                    `## ${pod.name}`,
                    `**Pod ID:** ${pod.id}`,
                    `**Members:** ${members.length}`,
                    members.length > 0 ? memberList : "  - No members assigned",
                    `**Created:** ${new Date(pod.created_at).toLocaleDateString()}`,
                    ""
                ].join('\n');
            })
        ].filter(Boolean).join('\n');

        return {
            content: [{
                type: "text",
                text: responseText
            }]
        };
    }
);

// 8. Get Platform Tasks (Task Management)
server.tool(
    "get-platform-tasks",
    "Get platform tasks from OnSecurity API via /platform/tasks endpoint. This shows task management data including retests, reviews, and other task types with assigned user names. Task types: 1=comment, 2=review, 3=retest requested, 4=new file, 5=exec review, 6=unknown, 7=new annotation, 8=pre-req. Filters for incomplete tasks by default.",
    {
        completed: z.boolean().optional().describe("Filter by completion status (default: false for incomplete tasks)"),
        snoozed: z.boolean().optional().describe("Filter by snoozed status"),
        sort: z.string().optional().describe("Sort parameter in format 'field-direction'. Available: id-asc, completed_at-asc, show_after-asc, created_at-asc, updated_at-asc, id-desc, completed_at-desc, show_after-desc, created_at-desc, updated_at-desc"),
        limit: z.number().optional().describe("Max results per page (e.g. 50)"),
        page: z.number().optional().describe("Page number (default: 1)"),
        includes: z.string().optional().describe("Include related data: 'client', 'task_users,client', 'task_users,task_users.user,client,round' for user names and pod info"),
        fields: z.string().optional().describe("Specific fields to return (e.g. '*,client.id,client.name,task_users.*')")
    },
    async (params) => {
        const filters: Record<string, string | number> = {};
        
        // Default to incomplete tasks unless explicitly specified
        if (params.completed !== undefined) {
            filters['completed-eq'] = params.completed ? 1 : 0;
        } else {
            filters['completed-eq'] = 0; // Default to incomplete tasks
        }
        
        if (params.snoozed !== undefined) {
            filters['snoozed-eq'] = params.snoozed ? 1 : 0;
        }
        
        const response = await fetchPage<ApiResponse<PlatformTask>>(
            'platform/tasks',
            params.page || 1,
            filters,
            params.sort || 'id-asc',
            params.includes || 'task_users,task_users.user,client',
            params.fields || '*,client.id,client.name,task_users.*,task_users.user.*',
            params.limit || 50
        );
        
        if (!response) {
            return {
                content: [{
                    type: "text",
                    text: "Error fetching platform tasks."
                }]
            };
        }

        // Extract round IDs from task URLs to get pod information
        const roundIdToPodMap: Record<number, number | null> = {};
        const findingToRoundMap: Record<number, number | null> = {};
        const podCache: Record<number, PlatformPod | null> = {};
        const roundIds = new Set<number>();
        const findingIds = new Set<number>();
        
        // Extract round IDs and finding IDs from task URLs
        for (const task of response.result) {
            if (task.url) {
                const testMatch = task.url.match(/\/tests\/(\d+)/);
                const findingMatch = task.url.match(/\/findings\/(\d+)/);
                const prerequisiteMatch = task.url.match(/\/test\/(\d+)\/prerequisites/);
                
                if (testMatch) {
                    const roundId = parseInt(testMatch[1]);
                    roundIds.add(roundId);
                } else if (findingMatch) {
                    const findingId = parseInt(findingMatch[1]);
                    findingIds.add(findingId);
                } else if (prerequisiteMatch) {
                    // Prerequisites are linked directly to rounds
                    const roundId = parseInt(prerequisiteMatch[1]);
                    roundIds.add(roundId);
                }
            }
        }
        
        // Fetch finding information to get their round IDs
        for (const findingId of findingIds) {
            try {
                const url = `${ONSECURITY_API_BASE}/findings/${findingId}`;
                const finding = await makeOnSecurityRequest<any>(url);
                
                if (finding && finding.round_id) {
                    findingToRoundMap[findingId] = finding.round_id;
                    roundIds.add(finding.round_id);
                } else {
                    findingToRoundMap[findingId] = null;
                }
            } catch (error) {
                findingToRoundMap[findingId] = null;
            }
        }
        
        // Fetch round information for the identified round IDs
        for (const roundId of roundIds) {
            try {
                const url = `${ONSECURITY_API_BASE}/rounds/${roundId}`;
                const round = await makeOnSecurityRequest<any>(url);
                
                if (round && round.pod_id) {
                    roundIdToPodMap[roundId] = round.pod_id;
                } else {
                    roundIdToPodMap[roundId] = null;
                }
            } catch (error) {
                roundIdToPodMap[roundId] = null;
            }
        }

        // Get unique pod IDs and fetch their details
        const uniquePodIds = [...new Set(Object.values(roundIdToPodMap).filter((id): id is number => id !== null))];
        
        for (const podId of uniquePodIds) {
            try {
                const podResponse = await fetchPage<ApiResponse<PlatformPod>>(
                    'platform/pods',
                    1,
                    { 'id-eq': podId },
                    'id-asc',
                    'pod_users,pod_users.user',
                    '*',
                    1
                );
                
                if (podResponse && podResponse.result.length > 0) {
                    podCache[podId!] = podResponse.result[0];
                } else {
                    podCache[podId!] = null;
                }
            } catch (error) {
                podCache[podId!] = null;
            }
        }
        
        // Map task types to readable names
        const taskTypeNames: Record<number, string> = {
            1: 'Comment',
            2: 'Review', 
            3: 'Retest Requested',
            4: 'New File',
            5: 'Executive Review',
            6: 'Unknown',
            7: 'New Annotation',
            8: 'Prerequisite'
        };
        
        // Group tasks by type and status
        const tasksByType = response.result.reduce((acc: any, task) => {
            const typeName = taskTypeNames[task.type] || `Unknown Type ${task.type}`;
            if (!acc[typeName]) acc[typeName] = [];
            acc[typeName].push(task);
            return acc;
        }, {});
        
        const responseText = [
            "# Platform Tasks",
            `Found ${response.total_results} tasks across ${response.total_pages} pages`,
            "",
            ...Object.entries(tasksByType).map(([type, tasks]: any) => [
                `## ${type} (${tasks.length})`,
                ...tasks.map((task: PlatformTask) => {
                    const clientName = task.client?.result?.name || task.client_name || 'Unknown Client';
                    const dueDate = task.due_date ? new Date(task.due_date).toLocaleDateString() : 'No due date';
                    const assignedUsers = task.task_users?.result?.length || 0;
                    
                    // Extract user names if available
                    const userNames = task.task_users?.result
                        ?.map(taskUser => {
                            if (taskUser.user?.result) {
                                const user = taskUser.user.result;
                                return `${user.forename} ${user.surname}${user.job_title ? ` (${user.job_title})` : ''}`;
                            }
                            return `User ${taskUser.user_id}`;
                        })
                        ?.join(', ') || 'None';
                    
                    // Get pod information from round mapping
                    let podInfo = 'Pod info not available';
                    if (task.url) {
                        const testMatch = task.url.match(/\/tests\/(\d+)/);
                        const findingMatch = task.url.match(/\/findings\/(\d+)/);
                        const prerequisiteMatch = task.url.match(/\/test\/(\d+)\/prerequisites/);
                        
                        let roundId: number | null = null;
                        
                        if (testMatch) {
                            roundId = parseInt(testMatch[1]);
                        } else if (findingMatch) {
                            const findingId = parseInt(findingMatch[1]);
                            roundId = findingToRoundMap[findingId];
                        } else if (prerequisiteMatch) {
                            roundId = parseInt(prerequisiteMatch[1]);
                        }
                        
                        if (roundId) {
                            const podId = roundIdToPodMap[roundId];
                            if (podId && podCache[podId]) {
                                const pod = podCache[podId];
                                const memberNames = pod?.pod_users?.result
                                    ?.map(member => {
                                        const user = member.user?.result;
                                        return user ? user.forename : `User ${member.user_id}`;
                                    })
                                    ?.slice(0, 3)  // Show max 3 names
                                    ?.join(', ') || '';
                                
                                if (memberNames) {
                                    const moreCount = (pod?.pod_users?.result?.length || 0) - 3;
                                    const moreText = moreCount > 0 ? `, +${moreCount} more` : '';
                                    podInfo = `${pod?.name} (${memberNames}${moreText})`;
                                } else {
                                    podInfo = `${pod?.name}`;
                                }
                            } else if (podId) {
                                podInfo = `Pod ${podId}`;
                            }
                        }
                    }
                    
                    return [
                        `### Task #${task.id} - ${clientName}`,
                        `**${task.name}**`,
                        task.description ? `*${task.description}*` : '',
                        `- Due: ${dueDate}`,
                        `- Pod: ${podInfo}`,
                        assignedUsers > 0 ? `- Assigned to: ${userNames}` : '- Assigned to: None',
                        task.url ? `- URL: ${task.url}` : '',
                        `- Created: ${new Date(task.created_at).toLocaleDateString()}`,
                        ''
                    ].filter(Boolean).join('\n');
                }),
                ""
            ].flat()),
            `Page ${response.page} of ${response.total_pages}`
        ].filter(Boolean).join('\n');
        
        return {
            content: [{
                type: "text",
                text: responseText
            }]
        };
    }
);

// 8. Get Time Logs (Time Tracking)
server.tool(
    "get-time-logs",
    "Get time logs from OnSecurity API. This shows time tracking data for pentester work hours logged against rounds and clients. Useful for time management and billing tracking.",
    {
        round_id: z.number().optional().describe("Filter by specific round ID"),
        user_id: z.number().optional().describe("Filter by specific user ID"),
        client_id: z.number().optional().describe("Filter by specific client ID"),
        date_from: z.string().optional().describe("Filter time logs from this date (YYYY-MM-DD format)"),
        date_to: z.string().optional().describe("Filter time logs up to this date (YYYY-MM-DD format)"),
        sort: z.string().optional().describe("Sort parameter: id-asc, round_id-asc, user_id-asc, client_id-asc, date-asc, id-desc, round_id-desc, user_id-desc, client_id-desc, date-desc"),
        limit: z.number().optional().describe("Max results per page (e.g. 50)"),
        page: z.number().optional().describe("Page number (default: 1)"),
        includes: z.string().optional().describe("Include related data: 'round', 'user', 'client', or combinations"),
        fields: z.string().optional().describe("Specific fields to return")
    },
    async (params) => {
        const filters: Record<string, string | number> = {};
        
        if (params.round_id) {
            filters['round_id-eq'] = params.round_id;
        }
        
        if (params.user_id) {
            filters['user_id-eq'] = params.user_id;
        }
        
        if (params.client_id) {
            filters['client_id-eq'] = params.client_id;
        }
        
        if (params.date_from) {
            filters['date-mte'] = params.date_from;
        }
        
        if (params.date_to) {
            filters['date-lte'] = params.date_to;
        }
        
        const response = await fetchPage<ApiResponse<PlatformTimeLog>>(
            'time-logs',
            params.page || 1,
            filters,
            params.sort || 'date-desc',
            params.includes || 'round,user,client',
            params.fields || '*',
            params.limit || 50
        );
        
        if (!response) {
            return {
                content: [{
                    type: "text",
                    text: "Error fetching time logs."
                }]
            };
        }
        
        // Group by date for better readability
        const logsByDate = response.result.reduce((acc: any, log) => {
            const date = log.date;
            if (!acc[date]) acc[date] = [];
            acc[date].push(log);
            return acc;
        }, {});
        
        const responseText = [
            "# Time Logs",
            `Found ${response.total_results} time entries across ${response.total_pages} pages`,
            "",
            ...Object.entries(logsByDate).map(([date, logs]: any) => {
                const totalTime = logs.reduce((sum: number, log: PlatformTimeLog) => {
                    // Handle time_logged object with time and period
                    const timeValue = log.time_logged?.time || 0;
                    return sum + timeValue;
                }, 0);
                
                return [
                    `## ${date} (${totalTime.toFixed(1)} hours total)`,
                    ...logs.map((log: PlatformTimeLog) => {
                        const timeValue = log.time_logged?.time || 0;
                        const period = log.time_logged?.period || 'hour';
                        const timeDisplay = `${timeValue}${period === 'hour' ? 'h' : 'm'}`;
                        
                        return [
                            `### Time Entry #${log.id}`,
                            `- **Time**: ${timeDisplay}`,
                            `- **Round**: ${log.round_id}`,
                            `- **User**: ${log.user_id}`,
                            `- **Client**: ${log.client_id}`,
                            log.notes ? `- **Notes**: ${log.notes}` : '',
                            log.description ? `- **Description**: ${log.description}` : '',
                            ''
                        ].filter(Boolean).join('\n');
                    }),
                    ""
                ].flat();
            }).flat(),
            `Page ${response.page} of ${response.total_pages}`
        ].filter(Boolean).join('\n');
        
        return {
            content: [{
                type: "text",
                text: responseText
            }]
        };
    }
);

// ==================== MCP RESOURCES FOR BETTER CONTEXT ====================

// Add resource for round summaries
server.resource(
    "round/{roundId}/full-context",
    "Get complete context for a round including all related data",
    async (request: any) => {
        const roundId = request.params?.roundId;
        const includes = 'client,findings,prerequisites,targets,targets.target_type,time_logs,round_team_users';
        const url = `${ONSECURITY_API_BASE}/rounds/${roundId}?include=${includes}`;
        const round = await makeOnSecurityRequest<any>(url);
        
        if (!round) {
            return {
                contents: [{
                    uri: `round/${roundId}/full-context`,
                    mimeType: "application/json",
                    text: JSON.stringify({ error: "Round not found" })
                }]
            };
        }
        
        return {
            contents: [{
                uri: `round/${roundId}/full-context`,
                mimeType: "application/json",
                text: JSON.stringify(round, null, 2)
            }]
        };
    }
);


// Start the server
async function main() {
    try {
        const transport = new StdioServerTransport();
        await server.connect(transport);
        console.error("OnSec MCP Server running on stdio");
    } catch (error) {
        console.error("Fatal error in main():", error);
        process.exit(1);
    }
}

main();
