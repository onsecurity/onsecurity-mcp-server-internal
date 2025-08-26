// Finding and vulnerability-related type definitions

export interface FindingFeature {
    id: number;
    name: string;
    description?: string;
    evidence?: string;
    recommendation?: string;
    remediation_complexity?: string;
    round_id: number;
    created_at: string;
    updated_at: string;
    cvss?: {
        score: number;
        severity_label: string;
    };
    status?: {
        label: string;
        description: string;
    };
    published: boolean;
    executive_description?: string;
    executive_risk?: string;
    executive_recommendation?: string;
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
    sort: string | null;
    includes: any[];
    total_results: number;
    total_pages: number;
    page: number;
    result: FindingFeature[];
}

export interface BlockFeature {
    id: number;
    name: string;
    round_type_id: number;
    approved: boolean;
    automation_approved: boolean;
    used_count: number;
    remediation_complexity?: string;
    ratings?: {
        cvss?: {
            score: number;
        };
    };
    cvss?: {
        score: number;
    };
    executive_description?: string;
    executive_risk?: string;
    executive_recommendation?: string;
    description?: string;
    evidence?: string;
    recommendation?: string;
    created_at: string;
    updated_at: string;
}