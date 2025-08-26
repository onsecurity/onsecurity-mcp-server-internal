// Data extraction utility functions
import type { RoundFeature } from '../types/index.js';

// Extract assessment types from targets
export function extractAssessmentTypes(round: RoundFeature): string[] {
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
export function extractActualTargets(round: RoundFeature): { value: string; type: string; notes?: string }[] {
    if (!round.targets?.result) return [];
    
    return round.targets.result
        .filter(target => target.hidden === false && target.value)
        .map(target => ({
            value: target.value!,
            type: target.target_type?.result?.name || 'Unknown',
            notes: target.notes || undefined
        }));
}

// Helper to extract team/pod information from round includes
export function extractTeamInfo(round: any): { pod?: string; team_leader?: string; team_members?: string[] } {
    const teamInfo: any = {};
    
    if (round.team_leader_user?.result) {
        teamInfo.team_leader = round.team_leader_user.result.name || round.team_leader_user.result.email;
    }
    
    if (round.round_team_users?.result) {
        teamInfo.team_members = round.round_team_users.result.map((u: any) => 
            u.name || u.email || `User ${u.id}`
        );
    }
    
    // Try to extract pod information from team data
    if (round.team_users?.result) {
        const podMatch = round.team_users.result.find((t: any) => 
            t.name?.toLowerCase().includes('pod')
        );
        if (podMatch) {
            teamInfo.pod = podMatch.name;
        }
    }
    
    return teamInfo;
}

// Helper to extract time tracking data from rounds
export function extractTimeData(round: any): { estimated: number; logged: number; remaining: number } {
    const timeData = {
        estimated: 0,
        logged: 0,
        remaining: 0
    };
    
    // Get estimate from round
    if (round.estimate) {
        timeData.estimated = round.estimate.time || 0;
    }
    
    // Calculate logged time from time_logs
    if (round.time_logs?.result) {
        timeData.logged = round.time_logs.result.reduce((sum: number, log: any) => 
            sum + (log.hours || 0), 0
        );
    }
    
    // Calculate remaining time
    timeData.remaining = Math.max(0, timeData.estimated - timeData.logged);
    
    return timeData;
}