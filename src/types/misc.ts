// Miscellaneous type definitions (notifications, prerequisites, reports, etc.)

export interface NotificationFeature {
    id: number;
    title: string;
    content?: string;
    created_at: string;
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
    sort: string | null;
    includes: any[];
    total_results: number;
    total_pages: number;
    page: number;
    result: NotificationFeature[];
}

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

export interface ClientReportTemplateFeature {
    id: number;
    client_id: number;
    name?: string;
    description?: string;
    template_type?: string;
    template_name?: string;
    is_default?: boolean;
    created_at: string;
    updated_at: string;
}