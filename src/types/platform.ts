// Platform-related type definitions (pods, tasks, users, time tracking)

export interface PlatformUser {
    id: number;
    forename: string;
    surname: string;
    job_title?: string;
    company?: string;
    has_avatar?: boolean;
}

export interface PlatformTaskUser {
    id: number;
    user_id: number;
    task_id: number;
    created_at: string;
    updated_at: string;
    user?: {
        object_type: string;
        type: string;
        includes: any[];
        many: boolean;
        name: string;
        result: PlatformUser;
    };
}

export interface PlatformPodUser {
    id: number;
    user_id: number;
    pod_id: number;
    role: string;
    created_at: string;
    updated_at: string;
    user?: {
        object_type: string;
        type: string;
        includes: any[];
        many: boolean;
        name: string;
        result: PlatformUser;
    };
}

export interface PlatformPod {
    id: number;
    name: string;
    created_at: string;
    updated_at: string;
    pod_users?: {
        object_type: string;
        type: string;
        includes: any[];
        many: boolean;
        name: string;
        result: PlatformPodUser[];
    };
}

export interface PlatformTask {
    id: number;
    client_id: number;
    client_name?: string;
    name: string;
    description?: string;
    url?: string;
    type: number;
    due_date?: string;
    completed_at?: string;
    completed_by_user_id?: number;
    show_after?: string;
    created_at: string;
    updated_at: string;
    task_users?: {
        object_type: string;
        type: string;
        includes: any[];
        many: boolean;
        name: string;
        result: PlatformTaskUser[];
    };
    client?: {
        object_type: string;
        type: string;
        includes: any[];
        many: boolean;
        name: string;
        result: {
            id: number;
            name: string;
        };
    };
    round?: {
        object_type: string;
        type: string;
        includes: any[];
        many: boolean;
        name: string;
        result: {
            id: number;
            name: string;
            pod_id?: number;
        };
    };
}

export interface PlatformTimeLog {
    id: number;
    round_id: number;
    user_id: number;
    client_id?: number;
    date: string;
    hours: number;
    minutes: number;
    time_logged?: number | { hours?: number; minutes?: number };
    description?: string;
    created_at: string;
    updated_at: string;
}