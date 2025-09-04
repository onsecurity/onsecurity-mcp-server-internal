// Data formatting utility functions
import type { 
    RoundFeature, 
    FindingFeature, 
    NotificationFeature, 
    PrerequisiteFeature, 
    BlockFeature, 
    ApiResponse 
} from '../types/index.js';
import { extractAssessmentTypes, extractActualTargets } from './extractors.js';

// Format Round data
export function formatRound(round: RoundFeature): string {
    const assessmentTypes = extractAssessmentTypes(round);
    const actualTargets = extractActualTargets(round);
    
    const result = [
        `Round ID: ${round.id}`,
        `Client ID: ${round.client_id}`,
        `Round Type: ${round.round_type_id === 1 ? "pentest round" : round.round_type_id === 3 ? "scan round" : round.round_type_id}`,
        `Pod ID: ${round.pod_id || "Not assigned"}`,
        `Estimated: ${round.estimate?.time || "N/A"} ${round.estimate?.period || ""}`,
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
export function formatFinding(finding: FindingFeature): string {
    return [
        `Finding ID: ${finding.id}`,
        `Name: ${finding.name}`,
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
export function formatNotification(notification: NotificationFeature): string {
    return [
        `Content: ${notification.title}`,
        `Created At: ${notification.created_at}`,
        `--------------------------------`,
    ].join('\n');
}

// Format Prerequisite data
export function formatPrerequisite(prerequisite: PrerequisiteFeature): string {
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
export function formatBlock(block: BlockFeature): string {
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
export function formatPaginationInfo<T>(response: ApiResponse<T>): string {
    return [
        `Page ${response.page} of ${response.total_pages}`,
        `Total Results: ${response.total_results}`,
        `Items Per Page: ${response.limit}`,
        `Next Page Available: ${response.links.next ? 'Yes' : 'No'}`,
        `Previous Page Available: ${response.links.previous ? 'Yes' : 'No'}`,
        `--------------------------------`,
    ].join('\n');
}