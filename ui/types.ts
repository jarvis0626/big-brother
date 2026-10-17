export type InvokeMethod =
  | "state"
  | "list_processes"
  | "watch"
  | "replay"
  | "pause"
  | "stop"
  | "settings"
  | "delete_session";

export interface Session {
  id: string;
  name: string;
  mode: string;
  status: string;
  started_at: string;
  ended_at?: string | null;
  root_key?: string;
  ancestry_complete?: boolean;
}

export interface ObservedProcess {
  key: string;
  pid: number;
  parent_key?: string | null;
  name: string;
  image?: string;
  command_line?: string;
  started_at?: string;
  ended_at?: string | null;
  uncertain?: boolean;
}

export interface ActivityEvent {
  id: string;
  session_id: string;
  process_key?: string;
  parent_key?: string;
  pid?: number;
  timestamp: string;
  ingested_at?: string;
  kind: string;
  image?: string;
  command_line?: string;
  details?: Record<string, unknown>;
  source: string;
  source_record_id?: string;
  uncertain?: boolean;
}

export interface EvidenceStatement {
  text: string;
  event_ids: string[];
}

export interface DocumentationReference {
  title?: string;
  name?: string;
  url?: string;
  id?: string;
  text?: string;
}

export interface Incident {
  id: string;
  session_id: string;
  title: string;
  severity: string;
  classification?: "reference_note" | "evidence_rule";
  score: number | null;
  score_kind: string;
  model_version: string;
  event_ids: string[];
  explanation: {
    observed: EvidenceStatement[];
    interpretations: (string | { text: string })[];
    missing: (string | { text: string })[];
    suggested: (string | { text: string })[];
    documentation: (DocumentationReference | string)[];
  };
}

export interface ModelAssessment {
  status: string;
  explanation?: string;
  reference_domain?: string;
  score?: number | null;
  threshold?: number | null;
  above_reference_threshold?: boolean;
  required_context_events?: number;
  available_context_events?: number;
  [key: string]: unknown;
}

export interface Coverage {
  kind: string;
  status: string;
  backend: string;
  detail: string;
}

export interface ModelInfo {
  name: string;
  version: string;
  status: string;
  threshold?: number | null;
  limitations?: string | string[];
  [key: string]: unknown;
}

export interface Settings {
  retention_days?: number;
  max_events?: number;
  poll_interval?: number;
  max_queue?: number;
  max_sessions?: number;
  close_to_tray?: boolean;
  llm_provider?: string;
  [key: string]: unknown;
}

export interface AppState {
  sessions: Session[];
  session: Session | null;
  events: ActivityEvent[];
  processes: ObservedProcess[];
  incidents: Incident[];
  behavior_notes?: Incident[];
  model_assessment?: ModelAssessment | null;
  collector: {
    status: string;
    backend: string;
    gaps: unknown[];
    dropped_events: number;
    [key: string]: unknown;
  };
  model: ModelInfo;
  settings: Settings;
  coverage: Coverage[];
  recording?: {
    provenance: {
      dataset: string;
      revision?: string;
      scenario_level_label?: string;
      provenance_status?: string;
      [key: string]: unknown;
    };
    coverage: {
      notes?: string[];
      missing_process_start_count?: number;
      missing_parent_count?: number;
      [key: string]: unknown;
    };
    imported_events: number;
    observed_kinds: string[];
  } | null;
  [key: string]: unknown;
}

export interface ProcessPickerEntry {
  pid: number;
  name: string;
  image?: string;
  command_line?: string;
  [key: string]: unknown;
}

export interface BigBrotherAPI {
  invoke<T = unknown>(
    method: InvokeMethod,
    params?: Record<string, unknown>,
  ): Promise<T>;
  selectExecutable(): Promise<{ path: string } | null>;
  launchSelected(): Promise<unknown>;
  importRecording(): Promise<Session | null>;
  exportReport(sessionId: string): Promise<unknown>;
  openExternal(url: string): Promise<unknown>;
}

declare global {
  interface Window {
    bigBrother?: BigBrotherAPI;
  }
}
