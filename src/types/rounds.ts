// Round-related type definitions

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
    pod_id?: number;
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

export interface RoundAutomationFeature {
    id: number;
    round_id: number;
    automation_type?: string;
    status?: 'pending' | 'running' | 'completed' | 'failed';
    started_at?: string;
    completed_at?: string;
    error_message?: string;
    created_at: string;
    updated_at: string;
}

export interface RoundArtifactFeature {
    id: number;
    round_id: number;
    filename?: string;
    file_type?: string;
    file_size?: number;
    uploaded_by?: number;
    description?: string;
    created_at: string;
    updated_at: string;
}