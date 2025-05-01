import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import 'dotenv/config';
import { 
  RoundFeature, 
  RoundResponse, 
  FindingFeature, 
  FindingResponse, 
  NotificationFeature, 
  NotificationResponse 
} from './types.js';


const ONSECURITY_API_BASE = "https://app.onsecurity.io/api/v2";
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
async function makeOnSecurityRequest<T>(url: string): Promise<T | null> {
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

//format Round data
function formatRound(round: RoundFeature): string {
    return [
        `client_id: ${round.client_id}`,
        `round_type: ${round.round_type_id === 1 ? "pentest round" : round.round_type_id === 3 ? "scan round" : round.round_type_id}`,
        `estimated: ${round.estimate.time} ${round.estimate.period}`,
        `start_date: ${round.start_date || "Unknown"}`,
        `end_date: ${round.end_date || "Unknown"}`,
        `started: ${round.started}`,
        `completed: ${round.finished}`,
        `name: ${round.name}`,
        `executive_summary_published: ${round.executive_summary_published}`,
        `--------------------------------`,
    ].join('\n');
}

//format Finding data
function formatFinding(finding: FindingFeature): string {
    return [
        `ID: ${finding.id}`,
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
        `ID: ${notification.id}`,
        `Heading: ${notification.heading}`,
        `Trigger Reference: ${notification.trigger_reference}`,
        `Trigger ID: ${notification.trigger_id}`,
        `Notifiable Type: ${notification.notifiable_type}`,
        `Notifiable ID: ${notification.notifiable_id}`,
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
        const roundsUrl = `${ONSECURITY_API_BASE}/rounds?filter[client_id-eq]={ADD CLIENT ID HERE FOR TESTING}`;
        const roundsData = await makeOnSecurityRequest<RoundResponse>(roundsUrl);

        if (!roundsData) {
            return{
                content: [
                    {
                        type: "text",
                        text: "Failed to fetch rounds data"
                    }
                ]
            }
        }

        const results = roundsData.result || [];
        const formattedRounds = results.map(formatRound);
        const responseText = `Here are the rounds data for the client: ${formattedRounds.join('\n\n')}`;

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
    "Get all findings data from OnSecurity from client in a high level summary, only include the summary, not the raw data and be sure to present the data in a way that is easy to understand for the client.",
    async () => {
        const findingsUrl = `${ONSECURITY_API_BASE}/findings?filter[client_id-eq]={ADD CLIENT ID HERE FOR TESTING}`;
        const findingsData = await makeOnSecurityRequest<FindingResponse>(findingsUrl);

        if (!findingsData) {
            return {
                content: [
                    {
                        type: "text",
                        text: "Failed to fetch findings data"
                    }
                ]
            }
        }

        const results = findingsData.result || [];
        const formattedFindings = results.map(formatFinding);
        const responseText = `Here are the findings data for the client: ${formattedFindings.join('\n\n')}`;

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
        const notificationsUrl = `${ONSECURITY_API_BASE}/notifications?filter[client_id-eq]={ADD CLIENT ID HERE FOR TESTING}`;
        const notificationsData = await makeOnSecurityRequest<NotificationResponse>(notificationsUrl);

        if (!notificationsData) {
            return {
                content: [
                    {
                        type: "text",
                        text: "Failed to fetch notifications data"
                    }
                ]
            }
        }

        const results = notificationsData.result || [];
        const formattedNotifications = results.map(formatNotification);
        const responseText = `Here are the notifications data for the client: ${formattedNotifications.join('\n\n')}`;

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