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
    id?: number;
    trigger_reference?: string;
    trigger_id?: string;
    notifiable_type?: string;
    notifiable_id?: number;
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