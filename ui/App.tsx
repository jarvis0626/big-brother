import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowRight,
  Check,
  ChevronDown,
  ChevronRight,
  Clock3,
  Cpu,
  Database,
  ExternalLink,
  FileCode2,
  FileText,
  FolderOpen,
  GitBranch,
  History,
  Info,
  LayoutDashboard,
  LoaderCircle,
  Network,
  Pause,
  Play,
  Plus,
  Radio,
  RefreshCw,
  Search,
  Settings2,
  Square,
  Terminal,
  Trash2,
  X,
  type LucideIcon,
} from "lucide-react";
import type {
  ActivityEvent,
  AppState,
  BigBrotherAPI,
  Coverage,
  DocumentationReference,
  Incident,
  InvokeMethod,
  ObservedProcess,
  ProcessPickerEntry,
  Session,
  Settings,
} from "./types";

type View = "overview" | "findings" | "sessions" | "settings";
type Modal = "process" | "executable" | "replay" | "delete" | null;
const EMPTY_STATE: AppState = {
  sessions: [],
  session: null,
  events: [],
  processes: [],
  incidents: [],
  behavior_notes: [],
  collector: {
    status: "connecting",
    backend: "Waiting for collector",
    gaps: [],
    dropped_events: 0,
  },
  model: { name: "Loading model", version: "—", status: "loading" },
  settings: {},
  coverage: [],
};

function api(): BigBrotherAPI {
  if (!window.bigBrother)
    throw new Error(
      "The desktop connection is unavailable. Open Big Brother from the Windows application.",
    );
  return window.bigBrother;
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function time(value?: string | null, withDate = false): string {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString(
    undefined,
    withDate
      ? { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }
      : {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false,
        },
  );
}

function fileName(value?: string): string {
  return value?.split(/[\\/]/).pop() || "Unknown process";
}

function label(value?: string): string {
  return (value || "unknown")
    .replace(/[_-]/g, " ")
    .replace(/^\w/, (c) => c.toUpperCase());
}

function isReplay(session?: Session | null): boolean {
  return !!session && /replay|demo/i.test(session.mode);
}

function isRecording(session?: Session | null): boolean {
  return session?.mode === "recording";
}

function isCollecting(status?: string): boolean {
  return ["running", "watching", "active", "collecting"].includes((status || "").toLowerCase());
}

function coverageAvailable(status: string): boolean {
  return ["supported", "available", "active", "enabled", "partial", "recorded"].includes(
    status.toLowerCase(),
  );
}

function sessionIdOf(value: unknown): string | undefined {
  if (!value || typeof value !== "object") return undefined;
  const item = value as { session_id?: string; id?: string; session?: Session };
  return item.session_id || item.session?.id || item.id;
}

const EVENT_NAMES: Record<string, string> = {
  process_create: "Process started",
  process_start: "Process started",
  process_end: "Process exited",
  process_exit: "Process exited",
  process_terminate: "Process exited",
  process_stop: "Process exited",
  process_access: "Process access",
  network_connect: "Network connection",
  network_connection: "Network connection",
  network: "Network connection",
  dns_query: "DNS query",
  dns: "DNS query",
  file_create: "File created",
  file_write: "File changed",
  file_delete: "File deleted",
  registry_set: "Registry changed",
  registry_change: "Registry changed",
  registry: "Registry changed",
  gap: "Collection gap",
};
function eventName(kind: string): string {
  return EVENT_NAMES[kind] || label(kind);
}
function eventIcon(kind: string): LucideIcon {
  if (/network|dns/i.test(kind)) return Network;
  if (/file/i.test(kind)) return FileText;
  if (/registry/i.test(kind)) return Database;
  if (/gap/i.test(kind)) return AlertTriangle;
  return Terminal;
}
function detailOf(event: ActivityEvent): string {
  const d = event.details || {};
  const meaningful = [
    "summary",
    "description",
    "target",
    "target_object",
    "path",
    "file_path",
    "destination",
    "destination_ip",
    "query_name",
    "query",
    "command_line",
  ];
  for (const key of meaningful) {
    if (d[key] !== undefined && d[key] !== null) {
      const value = String(d[key]);
      const port = d.destination_port || d.port;
      return /destination/.test(key) && port ? `${value}:${port}` : value;
    }
  }
  if (event.command_line && /process_create|process_start/.test(event.kind))
    return event.command_line;
  const entries = Object.entries(d).filter(([key]) => !["fabricated", "snapshot", "source_epoch"].includes(key))
    .slice(0, 3)
    .map(
      ([key, value]) =>
        `${label(key)}: ${typeof value === "object" ? JSON.stringify(value) : String(value)}`,
    );
  return entries.join(" · ") || event.image || eventName(event.kind);
}
function shortId(id: string): string {
  return id.length > 13 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id;
}

function Eye({
  className = "",
  size = 34,
}: {
  className?: string;
  size?: number;
}) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 256 256"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M38 128c22-34 53-52 90-52s68 18 90 52c-22 34-53 52-90 52s-68-18-90-52Z"
        stroke="#eeebea"
        strokeWidth="13"
        strokeLinejoin="round"
      />
      <circle cx="128" cy="128" r="27" fill="#c55258" />
      <circle cx="128" cy="128" r="10" fill="#14161b" />
    </svg>
  );
}

function Badge({
  children,
  tone = "neutral",
  dot = false,
}: {
  children: ReactNode;
  tone?: string;
  dot?: boolean;
}) {
  return (
    <span className={`badge badge-${tone}`}>
      {dot && <span className="status-dot" />}
      {children}
    </span>
  );
}

function Empty({
  icon: Icon = Activity,
  title,
  children,
  action,
}: {
  icon?: LucideIcon;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon">
        <Icon size={24} strokeWidth={1.5} />
      </span>
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

function ModalFrame({
  title,
  subtitle,
  onClose,
  children,
  footer,
  wide = false,
}: {
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prior = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    const handle = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
      if (event.key !== "Tab" || !ref.current) return;
      const elements = [
        ...ref.current.querySelectorAll<HTMLElement>(
          'button:not(:disabled),input:not(:disabled),select:not(:disabled),a[href],[tabindex="0"]',
        ),
      ];
      const first = elements[0];
      const last = elements[elements.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    };
    document.addEventListener("keydown", handle);
    return () => {
      document.removeEventListener("keydown", handle);
      prior?.focus();
    };
  }, [onClose]);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        className={`modal ${wide ? "modal-wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        tabIndex={-1}
      >
        <div className="modal-header">
          <div>
            <h2 id="modal-title">{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          <button
            className="icon-button"
            aria-label="Close dialog"
            onClick={onClose}
          >
            <X size={20} />
          </button>
        </div>
        <div className="modal-content">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  );
}

type ProcessNodeData = {
  process: ObservedProcess;
  root: boolean;
  flagged: boolean;
  selected: boolean;
};
type ProcessNode = Node<ProcessNodeData, "process">;
function ProcessCard({ data }: NodeProps<ProcessNode>) {
  const { process, root, flagged, selected } = data;
  const ended = !!process.ended_at;
  return (
    <div
      className={`process-node ${root ? "root-node" : ""} ${flagged ? "flagged-node" : ""} ${selected ? "selected-node" : ""}`}
    >
      <Handle type="target" position={Position.Left} />
      <div className="node-head">
        <span className={`node-icon ${flagged ? "node-icon-alert" : ""}`}>
          <Terminal size={16} />
        </span>
        <span className="node-name" title={process.name}>
          {process.name}
        </span>
        {flagged && (
          <AlertTriangle
            className="node-alert"
            size={14}
            aria-label="Associated with finding"
          />
        )}
      </div>
      <div className="node-meta">
        <span>PID {process.pid}</span>
        <span className={`node-status ${ended ? "ended" : ""}`}>
          <i />
          {ended ? "Exited" : "Observed"}
        </span>
      </div>
      {(root || process.uncertain) && (
        <div className="node-label">
          {process.uncertain ? "Association uncertain" : "Watched process"}
        </div>
      )}
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
const NODE_TYPES = { process: ProcessCard };

function ProcessGraph({
  state,
  selectedKey,
  onSelect,
}: {
  state: AppState;
  selectedKey: string | null;
  onSelect: (key: string) => void;
}) {
  const { nodes, edges } = useMemo(() => {
    const processMap = new Map(state.processes.map((p) => [p.key, p]));
    const flaggedKeys = new Set(
      state.incidents
        .flatMap((i) => i.event_ids)
        .flatMap((id) => {
          const e = state.events.find((event) => event.id === id);
          return e?.process_key ? [e.process_key] : [];
        }),
    );
    const depthMemo = new Map<string, number>();
    const depth = (key: string, visited = new Set<string>()): number => {
      if (depthMemo.has(key)) return depthMemo.get(key)!;
      if (visited.has(key)) return 0;
      visited.add(key);
      const parent = processMap.get(key)?.parent_key;
      const result =
        parent && processMap.has(parent) ? depth(parent, visited) + 1 : 0;
      depthMemo.set(key, result);
      return result;
    };
    const groups = new Map<number, ObservedProcess[]>();
    const sorted = [...state.processes].sort(
      (a, b) =>
        (a.started_at || "").localeCompare(b.started_at || "") ||
        a.key.localeCompare(b.key),
    );
    sorted.forEach((p) => {
      const d = depth(p.key);
      groups.set(d, [...(groups.get(d) || []), p]);
    });
    const maxGroup = Math.max(1, ...[...groups.values()].map((g) => g.length));
    const nodes: ProcessNode[] = sorted.map((p) => {
      const d = depth(p.key);
      const group = groups.get(d)!;
      const index = group.findIndex((v) => v.key === p.key);
      return {
        id: p.key,
        type: "process",
        position: {
          x: d * 250,
          y: index * 128 + (maxGroup - group.length) * 64,
        },
        data: {
          process: p,
          root: p.key === state.session?.root_key,
          flagged: flaggedKeys.has(p.key),
          selected: p.key === selectedKey,
        },
      };
    });
    const edges: Edge[] = sorted
      .filter((p) => p.parent_key && processMap.has(p.parent_key))
      .map((p) => ({
        id: `${p.parent_key}:${p.key}`,
        source: p.parent_key!,
        target: p.key,
        type: "smoothstep",
        markerEnd: {type: MarkerType.ArrowClosed, color: p.uncertain ? "#9b835d" : "#777f90", width: 14, height: 14},
        animated: false,
        style: {
          stroke: p.uncertain ? "#9b835d" : "#565b68",
          strokeWidth: 1.5,
          strokeDasharray: p.uncertain ? "5 5" : undefined,
        },
      }));
    return { nodes, edges };
  }, [
    state.processes,
    state.incidents,
    state.events,
    state.session?.root_key,
    selectedKey,
  ]);
  if (!nodes.length)
    return (
      <div className="graph-empty">
        <div className="graph-ghost">
          <span>
            <Terminal size={20} />
          </span>
          <i />
          <span>
            <GitBranch size={20} />
          </span>
          <i />
          <span>
            <Network size={20} />
          </span>
        </div>
        <h3>Your next investigation starts here</h3>
        <p>
          Choose a process to observe its descendants and available activity,
          <br className="desktop-break" /> or explore a recorded replay.
        </p>
      </div>
    );
  return (
    <ReactFlow
      key={state.session?.id}
      nodes={nodes}
      edges={edges}
      nodeTypes={NODE_TYPES}
      fitView
      fitViewOptions={{ padding: 0.23, maxZoom: 1 }}
      minZoom={0.15}
      maxZoom={1.5}
      nodesDraggable={false}
      nodesConnectable={false}
      onNodeClick={(_event, node) => onSelect(node.id)}
      proOptions={{ hideAttribution: true }}
    >
      <Background
        variant={BackgroundVariant.Dots}
        gap={22}
        size={1}
        color="#363940"
      />
      <Controls showInteractive={false} />
    </ReactFlow>
  );
}

function EventDetail({
  event,
  onClose,
}: {
  event: ActivityEvent;
  onClose: () => void;
}) {
  const detailRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    detailRef.current?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [event.id]);
  return (
    <div className="event-detail" ref={detailRef}>
      <div className="subpanel-heading">
        <h3>{eventName(event.kind)}</h3>
        <button
          className="icon-button small"
          aria-label="Close event details"
          onClick={onClose}
        >
          <X size={15} />
        </button>
      </div>
      <dl>
        <dt>Event ID</dt>
        <dd className="mono selectable">{event.id}</dd>
        <dt>Recorded</dt>
        <dd>{time(event.timestamp, true)}</dd>
        <dt>Source</dt>
        <dd>
          {event.source}
          {event.source_record_id ? ` · ${event.source_record_id}` : ""}
        </dd>
        {event.ingested_at && (
          <>
            <dt>Ingested</dt>
            <dd>{time(event.ingested_at, true)}</dd>
          </>
        )}
        {event.pid !== undefined && (
          <>
            <dt>Process ID</dt>
            <dd>{event.pid}</dd>
          </>
        )}
        {event.image && (
          <>
            <dt>Executable</dt>
            <dd className="mono selectable">{event.image}</dd>
          </>
        )}
        {event.command_line && (
          <>
            <dt>Command line</dt>
            <dd className="mono selectable">{event.command_line}</dd>
          </>
        )}
        {Object.entries(event.details || {}).map(([key, value]) => (
          <div className="detail-pair" key={key}>
            <dt>{label(key)}</dt>
            <dd className="mono selectable">
              {typeof value === "object"
                ? JSON.stringify(value, null, 2)
                : String(value)}
            </dd>
          </div>
        ))}
      </dl>
      {event.uncertain && (
        <div className="inline-note warning">
          <Info size={15} />
          This association is uncertain.
        </div>
      )}
    </div>
  );
}

function Timeline({
  state,
  selectedKey,
  selectedEventId,
  focusedIds,
  onEvent,
  onClearFilter,
}: {
  state: AppState;
  selectedKey: string | null;
  selectedEventId: string | null;
  focusedIds: string[];
  onEvent: (event: ActivityEvent) => void;
  onClearFilter: () => void;
}) {
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState("all");
  const rowRefs = useRef<Map<string, HTMLButtonElement>>(new Map());
  const kinds = useMemo(
    () => [...new Set(state.events.map((e) => e.kind))].sort(),
    [state.events],
  );
  const events = useMemo(
    () =>
      [...state.events]
        .filter(
          (e) =>
            (!selectedKey || e.process_key === selectedKey) &&
            (!focusedIds.length || focusedIds.includes(e.id)) &&
            (kind === "all" || e.kind === kind) &&
            (!search ||
              `${e.id} ${e.kind} ${e.image} ${e.command_line} ${JSON.stringify(e.details)}`
                .toLowerCase()
                .includes(search.toLowerCase())),
        )
        .sort(
          (a, b) =>
            a.timestamp.localeCompare(b.timestamp) || a.id.localeCompare(b.id),
        ),
    [state.events, selectedKey, focusedIds, kind, search],
  );
  useEffect(() => {
    if (selectedEventId)
      rowRefs.current
        .get(selectedEventId)
        ?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [selectedEventId]);
  useEffect(() => {
    setSearch("");
    setKind("all");
  }, [state.session?.id]);
  useEffect(() => {
    if (focusedIds.length > 0) {setSearch(""); setKind("all");}
  }, [focusedIds]);
  return (
    <section className="panel timeline-panel">
      <div className="panel-heading">
        <div className="heading-with-icon">
          <Clock3 size={17} />
          <h2>Evidence timeline</h2>
          <span className="count-pill">{events.length}</span>
        </div>
        <span className="quiet-text">Chronological order</span>
      </div>
      <div className="timeline-tools">
        <div className="search-box">
          <Search size={16} />
          <input
            aria-label="Search evidence"
            placeholder="Search events, paths, destinations…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button
              className="icon-button small"
              aria-label="Clear evidence search"
              onClick={() => setSearch("")}
            >
              <X size={14} />
            </button>
          )}
        </div>
        <div className="select-wrap">
          <select
            aria-label="Filter event type"
            value={kind}
            onChange={(e) => setKind(e.target.value)}
          >
            <option value="all">All event types</option>
            {kinds.map((k) => (
              <option value={k} key={k}>
                {eventName(k)}
              </option>
            ))}
          </select>
          <ChevronDown size={14} />
        </div>
      </div>
      {(selectedKey || focusedIds.length > 0) && (
        <div className="filter-notice">
          <GitBranch size={13} />
          <span>
            {focusedIds.length
              ? `Showing ${focusedIds.length} cited events`
              : `Filtered to ${state.processes.find((p) => p.key === selectedKey)?.name || "selected process"}`}
          </span>
          <button onClick={onClearFilter}>
            Clear filter <X size={12} />
          </button>
        </div>
      )}
      <div
        className="timeline-table"
        role="region"
        aria-label="Recorded events"
      >
        <div className="timeline-columns">
          <span>Time</span>
          <span>Activity / process</span>
          <span>Recorded detail</span>
          <span>Source</span>
        </div>
        <div className="timeline-rows">
          {events.length === 0 ? (
            <Empty
              icon={Clock3}
              title={
                state.events.length
                  ? "No matching events"
                  : "Waiting for evidence"
              }
            >
              {state.events.length
                ? "Try another search or clear the current filters."
                : "Recorded activity appears here when you start watching or open a replay."}
            </Empty>
          ) : (
            events.map((e) => {
              const Icon = eventIcon(e.kind);
              return (
                <button
                  ref={(el) => {
                    if (el) rowRefs.current.set(e.id, el);
                    else rowRefs.current.delete(e.id);
                  }}
                  className={`event-row ${selectedEventId === e.id ? "event-selected" : ""}`}
                  key={e.id}
                  onClick={() => onEvent(e)}
                  data-event-id={e.id}
                >
                  <span className="event-time mono">{time(e.timestamp)}</span>
                  <span className="event-activity">
                    <span className="event-kind-icon">
                      <Icon size={15} />
                    </span>
                    <span>
                      <strong>{eventName(e.kind)}</strong>
                      <small>
                        {fileName(e.image) || `PID ${e.pid}`}
                        {e.uncertain ? " · Uncertain" : ""}
                      </small>
                    </span>
                  </span>
                  <span className="event-summary" title={detailOf(e)}>
                    {detailOf(e)}
                  </span>
                  <span className="event-source">
                    {e.source}
                    <ChevronRight size={13} />
                  </span>
                </button>
              );
            })
          )}
        </div>
      </div>
      <div className="panel-foot">
        <span>Local evidence · {state.events.length} loaded events{state.session?.mode !== "recording" && state.events.length >= 2000 ? " · latest 2,000" : ""}</span>
        <span>Times shown in your local timezone</span>
      </div>
    </section>
  );
}

function ExplanationList({ items }: { items?: (string | { text: string })[] }) {
  if (!items?.length)
    return <p className="quiet-text">No additional information recorded.</p>;
  return (
    <ul className="explanation-list">
      {items.map((item, index) => (
        <li key={index}>{typeof item === "string" ? item : item.text}</li>
      ))}
    </ul>
  );
}

function IncidentDetail({
  incident,
  state,
  onEvidence,
  onExport,
}: {
  incident: Incident;
  state: AppState;
  onEvidence: (ids: string[]) => void;
  onExport: () => void;
}) {
  const explanation = incident.explanation;
  const referenceNote = incident.classification === "reference_note";
  return (
    <div className={`incident-detail ${referenceNote ? "behavior-detail" : ""}`}>
      <div className="incident-detail-title">
        <Badge tone={referenceNote ? "neutral" : incident.severity}>
          {referenceNote ? "Behavior note" : label(incident.severity)}
        </Badge>
        <h3>{incident.title}</h3>
      </div>
      <div className="score-card">
        <div>
          <span>{referenceNote ? "Difference from reference" : label(incident.score_kind || "anomaly score")}</span>
          <strong>
            {typeof incident.score === "number" &&
            Number.isFinite(incident.score)
              ? incident.score.toFixed(3)
              : "Rule"}
          </strong>
        </div>
        <div>
          <span>
            {typeof incident.score === "number"
              ? "Model version"
              : "Reference version"}
          </span>
          <code>{incident.model_version || state.model.version}</code>
        </div>
      </div>
      <p className="score-note">
        {referenceNote
          ? "This measures a difference from the model’s reference data. It does not establish a threat or check a server’s reputation or connection contents."
          : typeof incident.score === "number"
          ? "A measure of unusual behaviour, not a probability of maliciousness."
          : "This finding is based on a transparent evidence rule."}
      </p>
      <div className="explanation-section">
        <h4>
          <Activity size={14} />
          Observed facts
        </h4>
        {explanation?.observed?.length ? (
          explanation.observed.map((statement, index) => (
            <div className="observed-fact" key={index}>
              <p>{statement.text}</p>
              <div className="evidence-links">
                {statement.event_ids?.map((id) => (
                  <button
                    className="evidence-link mono"
                    key={id}
                    title={`Show event ${id}`}
                    onClick={() => onEvidence([id])}
                  >
                    <FileText size={11} />
                    {shortId(id)}
                  </button>
                ))}
              </div>
            </div>
          ))
        ) : (
          <p className="quiet-text">No observed statements were provided.</p>
        )}
      </div>
      <div className="explanation-section">
        <h4>
          <Info size={14} />
          Possible interpretations
        </h4>
        <ExplanationList items={explanation?.interpretations} />
      </div>
      <div className="explanation-section">
        <h4>
          <AlertTriangle size={14} />
          Missing information
        </h4>
        <ExplanationList items={explanation?.missing} />
      </div>
      <div className="explanation-section">
        <h4>
          <Search size={14} />
          Suggested checks
        </h4>
        <ExplanationList items={explanation?.suggested} />
      </div>
      {!!explanation?.documentation?.length && (
        <div className="explanation-section">
          <h4>
            <FileText size={14} />
            Supporting documentation
          </h4>
          <div className="documentation-list">
            {explanation.documentation.map((entry, index) => {
              const item: DocumentationReference =
                typeof entry === "string"
                  ? { url: entry, title: entry }
                  : entry;
              return item.url ? (
                <button
                  key={index}
                  onClick={() =>
                    void api()
                      .openExternal(item.url!)
                      .catch(() => {})
                  }
                >
                  <span>
                    {item.title || item.name || item.id || "Documentation"}
                  </span>
                  <ExternalLink size={13} />
                </button>
              ) : (
                <p key={index}>
                  {item.title || item.name || item.text || item.id}
                </p>
              );
            })}
          </div>
        </div>
      )}
      <div className="incident-actions">
        <button
          className="button secondary"
          onClick={() => onEvidence(incident.event_ids)}
        >
          <FileText size={15} />
          View all evidence
        </button>
        <button className="button secondary" onClick={onExport}>
          <ArrowDownToLine size={15} />
          Export report
        </button>
      </div>
    </div>
  );
}

function BehaviorNotesPanel({
  state,
  selectedId,
  onSelect,
  onEvidence,
  onExport,
}: {
  state: AppState;
  selectedId: string | null;
  onSelect: (id: string | null) => void;
  onEvidence: (ids: string[]) => void;
  onExport: () => void;
}) {
  const notes = state.behavior_notes || [];
  const selected = notes.find((note) => note.id === selectedId);
  const assessment = state.model_assessment;
  return (
    <section className="panel behavior-notes-panel" aria-label="Behavior notes">
      <div className="panel-heading">
        <div className="heading-with-icon">
          <Info size={17} />
          <h2>Behavior notes</h2>
          <span className="count-pill">{notes.length}</span>
        </div>
        <Badge tone="neutral">Reference only</Badge>
      </div>
      <div className="behavior-context">
        <p>{assessment?.explanation || "The model compares event patterns with its reference data. A difference is a note to inspect, not evidence that an app is malicious."}</p>
        <p>Normal games and other apps can connect on varied ports. Server reputation and connection contents are not checked.</p>
        {assessment?.reference_domain && <p className="behavior-reference">Reference data: {assessment.reference_domain}</p>}
        {assessment?.status === "insufficient_context" && <Badge tone="neutral">Waiting for more supported activity</Badge>}
      </div>
      {notes.length > 0 && <div className="behavior-picker">
        {notes.map((note) => (
          <button
            key={note.id}
            className={`behavior-choice ${note.id === selectedId ? "active" : ""}`}
            aria-expanded={note.id === selectedId}
            onClick={() => onSelect(note.id === selectedId ? null : note.id)}
          >
            <Info size={15} />
            <span>{note.title}</span>
            <span className="behavior-score">{typeof note.score === "number" && Number.isFinite(note.score) ? note.score.toFixed(3) : "Reference"}</span>
            <ChevronDown size={14} />
          </button>
        ))}
      </div>}
      {selected && <div className="behavior-note-content">
        <IncidentDetail incident={selected} state={state} onEvidence={onEvidence} onExport={onExport} />
      </div>}
    </section>
  );
}

function FindingsPanel({
  state,
  incidentId,
  onIncident,
  onEvidence,
  onExport,
  selectedEvent,
  onCloseEvent,
  selectedProcess,
  onClearProcess,
}: {
  state: AppState;
  incidentId: string | null;
  onIncident: (id: string) => void;
  onEvidence: (ids: string[]) => void;
  onExport: () => void;
  selectedEvent: ActivityEvent | undefined;
  onCloseEvent: () => void;
  selectedProcess?: ObservedProcess;
  onClearProcess: () => void;
}) {
  const active =
    state.incidents.find((i) => i.id === incidentId) || state.incidents[0];
  if (selectedEvent)
    return (
      <aside className="panel inspection-panel">
        <div className="panel-heading">
          <div className="heading-with-icon">
            <FileText size={17} />
            <h2>Event details</h2>
          </div>
          <Badge tone="neutral">Evidence</Badge>
        </div>
        <div className="inspection-scroll">
          <EventDetail event={selectedEvent} onClose={onCloseEvent} />
        </div>
      </aside>
    );
  if (selectedProcess)
    return (
      <aside className="panel inspection-panel">
        <div className="panel-heading">
          <div className="heading-with-icon">
            <Terminal size={17} />
            <h2>Process details</h2>
          </div>
          <button
            className="icon-button small"
            aria-label="Close process details"
            onClick={onClearProcess}
          >
            <X size={16} />
          </button>
        </div>
        <div className="inspection-scroll process-detail">
          <span className="large-process-icon">
            <Terminal size={25} />
          </span>
          <h3>{selectedProcess.name}</h3>
          <Badge dot tone="neutral">
            {selectedProcess.ended_at ? "Exited" : "Observed"}
          </Badge>
          <dl>
            <dt>Process ID</dt>
            <dd className="mono">{selectedProcess.pid}</dd>
            <dt>Stable identity</dt>
            <dd className="mono selectable">{selectedProcess.key}</dd>
            <dt>Executable</dt>
            <dd className="mono selectable">
              {selectedProcess.image || "Unavailable"}
            </dd>
            <dt>Command line</dt>
            <dd className="mono selectable">
              {selectedProcess.command_line || "Unavailable"}
            </dd>
            <dt>First observed</dt>
            <dd>{time(selectedProcess.started_at, true)}</dd>
            {selectedProcess.ended_at && (
              <>
                <dt>Exited</dt>
                <dd>{time(selectedProcess.ended_at, true)}</dd>
              </>
            )}
            {selectedProcess.parent_key && (
              <>
                <dt>Parent identity</dt>
                <dd className="mono selectable">
                  {selectedProcess.parent_key}
                </dd>
              </>
            )}
          </dl>
          {selectedProcess.uncertain && (
            <div className="inline-note warning">
              <Info size={15} />
              The association to this session is uncertain.
            </div>
          )}
          <div className="inline-note">
            <Info size={15} />
            Descendants remain in the session after their parent exits.
          </div>
          <button
            className="button secondary full-width"
            onClick={onClearProcess}
          >
            Return to findings
          </button>
        </div>
      </aside>
    );
  return (
    <aside className="panel inspection-panel">
      <div className="panel-heading">
        <div className="heading-with-icon">
          <AlertTriangle size={17} />
          <h2>Findings</h2>
          <span className="count-pill">{state.incidents.length}</span>
        </div>
      </div>
      {active ? (
        <>
          <div className="finding-picker">
            {state.incidents.map((i) => (
              <button
                key={i.id}
                className={`finding-choice ${active.id === i.id ? "active" : ""}`}
                onClick={() => onIncident(i.id)}
              >
                <span className={`finding-marker severity-${i.severity}`} />
                <span>{i.title}</span>
                <ChevronRight size={14} />
              </button>
            ))}
          </div>
          <div className="inspection-scroll">
            <IncidentDetail
              incident={active}
              state={state}
              onEvidence={onEvidence}
              onExport={onExport}
            />
          </div>
        </>
      ) : (
        <div className="inspection-scroll">
          <Empty icon={FileText} title="No findings recorded">
            Findings appear when observed activity warrants a closer look. No
            findings does not establish that an application is safe. Model
            comparisons appear separately under Behavior notes.
          </Empty>
          <div className="empty-panel-note">
            <Info size={16} />
            <p>
              Review telemetry coverage to understand what this session can
              observe.
            </p>
          </div>
        </div>
      )}
    </aside>
  );
}

function CoverageSummary({
  coverage,
  onOpen,
}: {
  coverage: Coverage[];
  onOpen: () => void;
}) {
  const available = coverage.filter((c) => coverageAvailable(c.status));
  const limited = coverage.length - available.length;
  return (
    <button className="coverage-summary" onClick={onOpen}>
      <Radio size={15} />
      <span>Telemetry coverage</span>
      <strong>
        {available.length}/{coverage.length || "—"}
      </strong>
      <span>
        {limited > 0
          ? `${limited} unavailable or disabled`
          : coverage.length
            ? "Review capabilities"
            : "Waiting for collector"}
      </span>
      <ChevronRight size={14} />
    </button>
  );
}

function SessionList({
  state,
  onSelect,
  onDelete,
  onExport,
}: {
  state: AppState;
  onSelect: (id: string) => void;
  onDelete: (session: Session) => void;
  onExport: (id: string) => void;
}) {
  const [query, setQuery] = useState("");
  const sessions = [...state.sessions]
    .filter((s) =>
      `${s.name} ${s.id} ${s.mode}`.toLowerCase().includes(query.toLowerCase()),
    )
    .sort((a, b) => b.started_at.localeCompare(a.started_at));
  return (
    <div className="sessions-view">
      <div className="view-intro">
        <div>
          <h2>Session history</h2>
          <p>Return to recorded activity and retained evidence.</p>
        </div>
        <div className="search-box">
          <Search size={16} />
          <input
            aria-label="Search sessions"
            placeholder="Search sessions…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </div>
      <section className="panel session-table-panel">
        <div className="session-table-head">
          <span>Application / session</span>
          <span>Mode</span>
          <span>Started</span>
          <span>Status</span>
          <span>Actions</span>
        </div>
        {sessions.length ? (
          sessions.map((s) => (
            <div className="session-table-row" key={s.id}>
              <button
                className="session-name-button"
                onClick={() => onSelect(s.id)}
              >
                <span className="session-icon">
                  <Terminal size={18} />
                </span>
                <span>
                  <strong>{s.name}</strong>
                  <small className="mono">{shortId(s.id)}</small>
                </span>
                <ChevronRight size={15} />
              </button>
              <span>
                <Badge tone={isRecording(s) ? "recording" : isReplay(s) ? "replay" : "neutral"}>
                  {isRecording(s) ? "Imported recording" : isReplay(s) ? "Replay" : "Live observation"}
                </Badge>
              </span>
              <span>{time(s.started_at, true)}</span>
              <span>
                <Badge dot tone={isCollecting(s.status) ? "live" : "neutral"}>
                  {label(s.status)}
                </Badge>
              </span>
              <span className="session-row-actions">
                <button
                  className="icon-button"
                  title="Export session report"
                  aria-label={`Export ${s.name}`}
                  onClick={() => onExport(s.id)}
                >
                  <ArrowDownToLine size={16} />
                </button>
                <button
                  className="icon-button"
                  title="Delete retained session"
                  aria-label={`Delete ${s.name}`}
                  onClick={() => onDelete(s)}
                >
                  <Trash2 size={15} />
                </button>
              </span>
            </div>
          ))
        ) : (
          <Empty
            icon={History}
            title={query ? "No matching sessions" : "No sessions yet"}
          >
            {query
              ? "Try another application name."
              : "Start watching a process or open a replay to create your first session."}
          </Empty>
        )}
        <div className="panel-foot">
          <span>{sessions.length} sessions</span>
          <span>Retention: {state.settings.retention_days ?? "—"} days</span>
        </div>
      </section>
      <div className="history-note">
        <Database size={18} />
        <p>
          Evidence is stored locally on this device. Delete a session to remove
          its events, process relationships and findings.
        </p>
      </div>
    </div>
  );
}

function SettingsView({
  state,
  busy,
  onSave,
  onStop,
}: {
  state: AppState;
  busy: boolean;
  onSave: (settings: Settings) => Promise<void>;
  onStop: () => void;
}) {
  const [retention, setRetention] = useState(
    Number(state.settings.retention_days || 7),
  );
  const [eventLimit, setEventLimit] = useState(
    Number(state.settings.max_events || 20000),
  );
  const [interval, setIntervalValue] = useState(
    Number(state.settings.poll_interval || 1),
  );
  const [queueLimit, setQueueLimit] = useState(
    Number(state.settings.max_queue || 4096),
  );
  const [sessionLimit, setSessionLimit] = useState(
    Number(state.settings.max_sessions || 20),
  );
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    setRetention(Number(state.settings.retention_days || 7));
    setEventLimit(Number(state.settings.max_events || 20000));
    setIntervalValue(Number(state.settings.poll_interval || 1));
    setQueueLimit(Number(state.settings.max_queue || 4096));
    setSessionLimit(Number(state.settings.max_sessions || 20));
  }, [
    state.settings.retention_days,
    state.settings.max_events,
    state.settings.poll_interval,
    state.settings.max_queue,
    state.settings.max_sessions,
  ]);
  const limitations = state.model.limitations
    ? Array.isArray(state.model.limitations)
      ? state.model.limitations
      : [state.model.limitations]
    : [];
  const gaps = (state.collector.gaps || []).map((gap) => {
    if (gap && typeof gap === "object") {
      const item = gap as {timestamp?: string; detail?: unknown};
      return {timestamp: item.timestamp, detail: String(item.detail || "Monitoring gap recorded")};
    }
    return {timestamp: undefined, detail: String(gap)};
  });
  const save = async () => {
    try {
      await onSave({
        retention_days: retention,
        max_events: eventLimit,
        poll_interval: interval,
        max_queue: queueLimit,
        max_sessions: sessionLimit,
      });
      setSaved(true);
      window.setTimeout(() => setSaved(false), 3500);
    } catch {
      /* The parent displays the actual backend error. */
    }
  };
  return (
    <div className="settings-view">
      <div className="view-intro">
        <div>
          <h2>Collection & privacy</h2>
          <p>Understand coverage and control what stays on this device.</p>
        </div>
      </div>
      <div className="settings-grid">
        <section className="panel">
          <div className="panel-heading">
            <div className="heading-with-icon">
              <Database size={17} />
              <h2>Retention & resource limits</h2>
            </div>
          </div>
          <div className="settings-content">
            <label className="setting-field">
              <span>
                <strong>Keep recorded evidence</strong>
                <small>
                  Older retained sessions are removed automatically.
                </small>
              </span>
              <span className="number-input">
                <input
                  type="number"
                  aria-label="Retention days"
                  value={retention}
                  min={1}
                  max={90}
                  onChange={(e) => setRetention(Number(e.target.value))}
                />
                <em>days</em>
              </span>
            </label>
            <label className="setting-field">
              <span>
                <strong>Total retained events</strong>
                <small>Limit stored event volume across all sessions.</small>
              </span>
              <span className="number-input">
                <input
                  type="number"
                  aria-label="Maximum retained events"
                  value={eventLimit}
                  min={500}
                  max={100000}
                  step={100}
                  onChange={(e) => setEventLimit(Number(e.target.value))}
                />
              </span>
            </label>
            <label className="setting-field">
              <span>
                <strong>Process polling interval</strong>
                <small>
                  Longer intervals reduce overhead and can miss short activity.
                </small>
              </span>
              <span className="number-input">
                <input
                  type="number"
                  aria-label="Polling interval seconds"
                  value={interval}
                  min={0.5}
                  max={10}
                  step={0.5}
                  onChange={(e) => setIntervalValue(Number(e.target.value))}
                />
                <em>sec</em>
              </span>
            </label>
            <label className="setting-field">
              <span>
                <strong>Ingestion queue limit</strong>
                <small>Bound pending events; dropped evidence is reported as a gap.</small>
              </span>
              <span className="number-input">
                <input type="number" aria-label="Ingestion queue limit" value={queueLimit}
                  min={128} max={16384} step={128}
                  onChange={(e) => setQueueLimit(Number(e.target.value))}/>
              </span>
            </label>
            <label className="setting-field">
              <span>
                <strong>Concurrent observations</strong>
                <small>Maximum number of watched or paused live sessions.</small>
              </span>
              <span className="number-input">
                <input type="number" aria-label="Concurrent observation limit" value={sessionLimit}
                  min={1} max={100}
                  onChange={(e) => setSessionLimit(Number(e.target.value))}/>
              </span>
            </label>
            <div className="settings-save">
              <button
                className="button primary"
                disabled={
                  busy ||
                  retention < 1 ||
                  retention > 90 ||
                  eventLimit < 500 ||
                  eventLimit > 100000 ||
                  interval < 0.5 ||
                  interval > 10 ||
                  queueLimit < 128 ||
                  queueLimit > 16384 ||
                  sessionLimit < 1 ||
                  sessionLimit > 100 ||
                  !Number.isInteger(retention) ||
                  !Number.isInteger(eventLimit) ||
                  !Number.isInteger(queueLimit) ||
                  !Number.isInteger(sessionLimit)
                }
                onClick={() => void save()}
              >
                {busy ? (
                  <LoaderCircle size={15} className="spin" />
                ) : saved ? (
                  <Check size={15} />
                ) : (
                  <Settings2 size={15} />
                )}{" "}
                {saved ? "Settings saved" : "Save settings"}
              </button>
            </div>
          </div>
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div className="heading-with-icon">
              <Cpu size={17} />
              <h2>Active reference model</h2>
            </div>
            <Badge
              tone={
                state.model.status === "ready" ||
                state.model.status === "loaded"
                  ? "live"
                  : "neutral"
              }
            >
              {label(state.model.status)}
            </Badge>
          </div>
          <div className="settings-content model-details">
            <h3>{state.model.name}</h3>
            <dl>
              <dt>Version</dt>
              <dd className="mono">{state.model.version}</dd>
              <dt>Reference comparison threshold</dt>
              <dd className="mono">
                {typeof state.model.threshold === "number"
                  ? state.model.threshold.toFixed(3)
                  : "Unavailable"}
              </dd>
              <dt>Explanation</dt>
              <dd>Local evidence templates and documentation</dd>
            </dl>
            {limitations.length > 0 && (
              <>
                <h4>Model limitations</h4>
                <ExplanationList items={limitations} />
              </>
            )}
            <div className="inline-note">
              <Info size={15} />
              Scores describe differences from the model’s reference data and
              appear as neutral behavior notes. They do not establish malicious intent.
            </div>
          </div>
        </section>
      </div>
      <section className="panel coverage-panel">
        <div className="panel-heading">
          <div className="heading-with-icon">
            <Radio size={17} />
            <h2>Telemetry capabilities</h2>
          </div>
          <span className="quiet-text">{state.collector.backend}</span>
        </div>
        <div className="coverage-table">
          <div className="coverage-row coverage-head">
            <span>Activity</span>
            <span>Availability</span>
            <span>Backend</span>
            <span>Coverage and requirements</span>
          </div>
          {state.coverage.length ? (
            state.coverage.map((c, index) => (
              <div className="coverage-row" key={`${c.kind}:${index}`}>
                <strong>{eventName(c.kind)}</strong>
                <span>
                  <Badge
                    tone={c.status === "recorded" ? "recording" : coverageAvailable(c.status) ? "live" : "neutral"}
                  >
                    {label(c.status)}
                  </Badge>
                </span>
                <span>{c.backend}</span>
                <p>{c.detail}</p>
              </div>
            ))
          ) : (
            <Empty icon={Radio} title="Coverage unavailable">
              Connect to the desktop collector to inspect its capabilities.
            </Empty>
          )}
        </div>
        <div className="coverage-setup">
          <Info size={17} />
          <div>
            <strong>Optional Sysmon telemetry</strong>
            <p>
              Big Brother can read an existing configured Sysmon Event Log.
              Sysmon runs a privileged service and driver. Installation, licence
              acceptance and event configuration are separate explicit steps.
            </p>
            <button
              className="text-button"
              onClick={() =>
                void api().openExternal(
                  "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
                )
              }
            >
              Review Microsoft setup documentation <ExternalLink size={13} />
            </button>
          </div>
        </div>
      </section>
      <section className="panel">
        <div className="panel-heading">
          <div className="heading-with-icon">
            <Activity size={17} />
            <h2>Background collection</h2>
          </div>
          <Badge
            dot
            tone={isCollecting(state.collector.status) ? "live" : "neutral"}
          >
            {label(state.collector.status)}
          </Badge>
        </div>
        <div className="background-settings">
          <div>
            <p>
              Closing the window keeps Big Brother in the system tray. Use the
              tray menu to reopen it, stop collection or exit.
            </p>
            <p>
              Stopping Big Brother collection does not stop a separately
              installed Sysmon service.
            </p>
            {state.collector.gaps?.length > 0 && (
              <div className="gap-note">
                <AlertTriangle size={15} />
                {state.collector.gaps.length} recorded collection gaps, listed below.
              </div>
            )}
            {state.collector.dropped_events > 0 && (
              <div className="gap-note">
                <AlertTriangle size={15} />
                {state.collector.dropped_events} events dropped by resource
                limits.
              </div>
            )}
          </div>
          <button className="button secondary" disabled={busy} onClick={onStop}>
            <Square size={14} />
            Stop all monitoring
          </button>
        </div>
        {gaps.length > 0 && <div className="gap-history" aria-label="Recorded monitoring gaps">
          <h3>Recorded monitoring gaps</h3>
          {gaps.map((gap, index) => <div className="gap-history-row" key={index}>
            <span className="mono">{time(gap.timestamp, true)}</span>
            <p>{gap.detail}</p>
          </div>)}
        </div>}
      </section>
      <div className="privacy-note">
        <Database size={17} />
        <p>
          Process paths and command lines can contain sensitive information.
          Core monitoring and explanations run locally; no external LLM or paid
          API is required.
        </p>
      </div>
    </div>
  );
}

export default function App() {
  const [state, setState] = useState<AppState>(EMPTY_STATE);
  const [view, setView] = useState<View>("overview");
  const [selectedSessionId, setSelectedSessionId] = useState<
    string | undefined
  >();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(
    null,
  );
  const [selectedBehaviorNoteId, setSelectedBehaviorNoteId] = useState<string | null>(null);
  const [focusedIds, setFocusedIds] = useState<string[]>([]);
  const [modal, setModal] = useState<Modal>(null);
  const [busy, setBusy] = useState(false);
  const [initialLoading, setInitialLoading] = useState(true);
  const [connectionError, setConnectionError] = useState("");
  const [actionError, setActionError] = useState("");
  const [toast, setToast] = useState("");
  const [pickerProcesses, setPickerProcesses] = useState<ProcessPickerEntry[]>(
    [],
  );
  const [pickerLoading, setPickerLoading] = useState(false);
  const [pickerSearch, setPickerSearch] = useState("");
  const [pickerPid, setPickerPid] = useState<number | null>(null);
  const [executablePath, setExecutablePath] = useState("");
  const [replayScenario, setReplayScenario] = useState("investigation");
  const [deleteTarget, setDeleteTarget] = useState<Session | null>(null);
  const requestSequence = useRef(0);
  const selectedSessionRef = useRef(selectedSessionId);
  selectedSessionRef.current = selectedSessionId;

  const refresh = useCallback(
    async (sessionId = selectedSessionRef.current) => {
      const sequence = ++requestSequence.current;
      try {
        const result = await api().invoke<AppState>(
          "state",
          sessionId ? { session_id: sessionId } : {},
        );
        if (sequence !== requestSequence.current) return;
        setState({
          ...EMPTY_STATE,
          ...result,
          collector: { ...EMPTY_STATE.collector, ...result.collector },
          model: { ...EMPTY_STATE.model, ...result.model },
        });
        setConnectionError("");
      } catch (error) {
        if (sequence === requestSequence.current)
          setConnectionError(errorText(error));
      } finally {
        if (sequence === requestSequence.current) setInitialLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 1500);
    return () => window.clearInterval(timer);
  }, [refresh]);
  useEffect(() => {
    void refresh(selectedSessionId);
    setSelectedKey(null);
    setSelectedEventId(null);
    setSelectedIncidentId(null);
    setSelectedBehaviorNoteId(null);
    setFocusedIds([]);
  }, [selectedSessionId, refresh]);
  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(""), 5000);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const run = async <T,>(
    action: () => Promise<T>,
    after?: (result: T) => void,
  ): Promise<T | undefined> => {
    setBusy(true);
    setActionError("");
    try {
      const result = await action();
      after?.(result);
      await refresh();
      return result;
    } catch (error) {
      setActionError(errorText(error));
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  const startSession = (result: unknown) => {
    const id = sessionIdOf(result);
    if (id) {
      selectedSessionRef.current = id;
      setSelectedSessionId(id);
    }
    setModal(null);
    setView("overview");
    setSelectedKey(null);
    setSelectedEventId(null);
    setFocusedIds([]);
  };
  const invokeAction = (
    method: InvokeMethod,
    params?: Record<string, unknown>,
    after?: (result: unknown) => void,
  ) => run(() => api().invoke(method, params), after);
  const closeModal = useCallback(() => {
    setModal(null);
    setActionError("");
  }, []);
  const loadProcesses = async () => {
    setPickerLoading(true);
    setActionError("");
    try {
      const result = await api().invoke<
        ProcessPickerEntry[] | { processes: ProcessPickerEntry[] }
      >("list_processes");
      setPickerProcesses(
        Array.isArray(result) ? result : result.processes || [],
      );
    } catch (error) {
      setActionError(errorText(error));
    } finally {
      setPickerLoading(false);
    }
  };
  const openProcessPicker = () => {
    setPickerPid(null);
    setPickerSearch("");
    setModal("process");
    void loadProcesses();
  };
  const chooseExecutable = async () => {
    await run(
      () => api().selectExecutable(),
      (result) => {
        if (result) {
          setExecutablePath(result.path);
          setModal("executable");
        }
      },
    );
  };
  const importRecording = async () => {
    await run(() => api().importRecording(), (result) => {
      if (result) {
        startSession(result);
        setToast("Recording imported. Recorded commands are never executed.");
      }
    });
  };
  const exportReport = async (id = state.session?.id) => {
    if (id)
      await run(
        () => api().exportReport(id),
        (result) => {
          if (
            result &&
            !(
              typeof result === "object" &&
              "canceled" in result &&
              result.canceled
            )
          )
            setToast("Report exported.");
        },
      );
  };
  const selectSession = (id: string) => {
    setSelectedSessionId(id);
    setView("overview");
  };
  const showEvidence = (ids: string[]) => {
    setSelectedKey(null);
    setFocusedIds(ids);
    setSelectedEventId(ids.length === 1 ? ids[0] : null);
    setView("overview");
  };
  const clearFilter = () => {
    setSelectedKey(null);
    setFocusedIds([]);
  };
  const saveSettings = async (settings: Settings) => {
    const result = await run(() => api().invoke("settings", settings));
    if (result === undefined) throw new Error("Settings were not saved.");
    setToast("Collection settings saved.");
  };
  const filteredPicker = pickerProcesses.filter((p) =>
    `${p.name} ${p.pid} ${p.image || ""}`
      .toLowerCase()
      .includes(pickerSearch.toLowerCase()),
  );
  const selectedProcess = state.processes.find((p) => p.key === selectedKey);
  const selectedEvent = state.events.find((e) => e.id === selectedEventId);
  const replay = isReplay(state.session);
  const recording = isRecording(state.session);
  const title = {
    overview: "Activity overview",
    findings: "Findings",
    sessions: "Sessions",
    settings: "Settings",
  }[view];
  const live = isCollecting(state.collector.status);
  const current = state.session;
  const capabilities = state.coverage.filter((c) =>
    coverageAvailable(c.status),
  ).length;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-eye">
            <Eye size={35} />
          </span>
          <span>Big Brother</span>
        </div>
        <div className="workspace-label">WORKSPACE</div>
        <nav className="main-nav" aria-label="Main navigation">
          {(
            [
              { id: "overview", text: "Overview", icon: LayoutDashboard },
              { id: "findings", text: "Findings", icon: AlertTriangle },
              { id: "sessions", text: "Sessions", icon: History },
            ] as const
          ).map((item) => (
            <button
              key={item.id}
              className={`nav-item ${view === item.id ? "active" : ""}`}
              onClick={() => setView(item.id)}
            >
              <item.icon size={18} />
              <span>{item.text}</span>
              {item.id === "findings" && state.incidents.length > 0 && (
                <span className="nav-count">{state.incidents.length}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-section-head">
          <span>RECENT SESSIONS</span>
          <button
            className="icon-button small"
            aria-label="New session"
            title="Watch a process"
            onClick={openProcessPicker}
          >
            <Plus size={15} />
          </button>
        </div>
        <div className="sidebar-sessions">
          {state.sessions.slice(0, 5).map((s) => (
            <button
              key={s.id}
              className={`sidebar-session ${current?.id === s.id ? "selected" : ""}`}
              onClick={() => selectSession(s.id)}
            >
              <span
                className={`session-dot ${isCollecting(s.status) ? "running" : ""}`}
              />
              <span>
                <strong title={s.name}>{s.name}</strong>
                <small>{isRecording(s) ? "Imported recording" : isReplay(s) ? "Replay" : label(s.status)}</small>
              </span>
            </button>
          ))}
          {!state.sessions.length && (
            <p className="sidebar-empty">Your sessions will appear here.</p>
          )}
        </div>
        <button
          className="sidebar-replay"
          onClick={() => {
            setModal("replay");
            setActionError("");
          }}
        >
          <span className="replay-icon">
            <Play size={15} />
          </span>
          <span>
            <strong>Explore a replay</strong>
            <small>Recorded example activity</small>
          </span>
          <ChevronRight size={15} />
        </button>
        <div className="sidebar-bottom">
          <button
            className={`nav-item ${view === "settings" ? "active" : ""}`}
            onClick={() => setView("settings")}
          >
            <Settings2 size={18} />
            <span>Settings</span>
          </button>
          <div className="local-indicator">
            <Database size={13} />
            <span>Stored on this device</span>
          </div>
          <div className="sidebar-version">
            Big Brother <span>v1.1.0</span>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace
            <ChevronRight size={13} />
            <strong>{title}</strong>
          </div>
          <div className="topbar-right">
            <span className="collector-indicator">
              <span className={`status-dot ${live ? "live" : ""}`} />
              {connectionError
                ? "Collector disconnected"
                : `Collector ${state.collector.status}`}
            </span>
            <span className="topbar-divider" />
            <button
              className="icon-button"
              title="Refresh activity"
              aria-label="Refresh activity"
              onClick={() => void refresh()}
            >
              <RefreshCw size={16} className={initialLoading ? "spin" : ""} />
            </button>
          </div>
        </header>
        <main className="main-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                {view === "overview"
                  ? "APPLICATION ACTIVITY"
                  : "YOUR WORKSPACE"}
              </div>
              <h1>{title}</h1>
              <p>
                {view === "overview"
                  ? "Live activity and recorded evidence for the selected session."
                  : view === "findings"
                    ? "Review unusual behaviour against the recorded evidence."
                    : view === "sessions"
                      ? "Locally retained investigations and recorded replays."
                      : "Collection, telemetry and model information."}
              </p>
            </div>
            <div className="primary-actions">
              <button
                className="button secondary"
                disabled={busy}
                onClick={() => void importRecording()}
              >
                <FileText size={16} />
                <span>Import recording</span>
              </button>
              <button
                className="button secondary"
                disabled={busy}
                onClick={() => void chooseExecutable()}
              >
                <FolderOpen size={16} />
                <span>Select executable</span>
              </button>
              <button
                className="button primary"
                disabled={busy}
                onClick={openProcessPicker}
              >
                <Plus size={16} />
                <span>Watch a process</span>
              </button>
            </div>
          </div>
          {connectionError && (
            <div className="error-banner" role="alert">
              <AlertTriangle size={17} />
              <div>
                <strong>Desktop connection unavailable</strong>
                <p>{connectionError}</p>
              </div>
              <button
                className="button secondary compact"
                onClick={() => void refresh()}
              >
                Retry
              </button>
            </div>
          )}
          {actionError && !modal && (
            <div className="error-banner" role="alert">
              <AlertTriangle size={17} />
              <span>{actionError}</span>
              <button
                className="icon-button small"
                aria-label="Dismiss error"
                onClick={() => setActionError("")}
              >
                <X size={16} />
              </button>
            </div>
          )}
          {view === "overview" && (
            <>
              <div className="session-toolbar">
                <div className="session-selector">
                  <span className="toolbar-session-icon">
                    <Terminal size={18} />
                  </span>
                  <div>
                    <span className="toolbar-label">CURRENT SESSION</span>
                    {state.sessions.length ? (
                      <div className="session-select-wrap">
                        <select
                          aria-label="Current session"
                          value={current?.id || ""}
                          onChange={(e) => setSelectedSessionId(e.target.value)}
                        >
                          {state.sessions.map((s) => (
                            <option value={s.id} key={s.id}>
                              {s.name}
                            </option>
                          ))}
                        </select>
                        <ChevronDown size={14} />
                      </div>
                    ) : (
                      <strong>No active session</strong>
                    )}
                  </div>
                  {current && (
                    <Badge
                      tone={
                        recording
                          ? "recording"
                          : replay
                          ? "replay"
                          : isCollecting(current.status)
                            ? "live"
                            : "neutral"
                      }
                      dot={!replay && !recording}
                    >
                      {recording ? "Imported recording" : replay ? "Replay · fabricated" : label(current.status)}
                    </Badge>
                  )}
                </div>
                <div className="session-controls">
                  {current && (
                    <>
                      <span className="session-start">
                        {recording ? "Imported" : "Started"} {time(current.started_at)}
                      </span>
                      {!replay && !recording &&
                        (isCollecting(current.status) ||
                          current.status === "paused") && (
                          <button
                            className="button secondary compact"
                            disabled={busy}
                            onClick={() =>
                              void invokeAction("pause", {
                                session_id: current.id,
                                paused: current.status !== "paused",
                              })
                            }
                          >
                            {current.status === "paused" ? (
                              <Play size={13} />
                            ) : (
                              <Pause size={13} />
                            )}{" "}
                            {current.status === "paused"
                              ? "Resume analysis"
                              : "Pause analysis"}
                          </button>
                        )}
                      {isCollecting(current.status) ||
                      current.status === "paused" ? (
                        <button
                          className="icon-button"
                          disabled={busy}
                          title="Stop watching this session"
                          aria-label="Stop session"
                          onClick={() =>
                            void invokeAction("stop", {
                              session_id: current.id,
                            })
                          }
                        >
                          <Square size={14} />
                        </button>
                      ) : null}
                      <button
                        className="button secondary compact"
                        disabled={busy}
                        onClick={() => void exportReport()}
                      >
                        <ArrowDownToLine size={14} />
                        Export
                      </button>
                    </>
                  )}
                  {!current && (
                    <button
                      className="text-button"
                      onClick={() => {
                        setModal("replay");
                        setActionError("");
                      }}
                    >
                      <Play size={13} />
                      Open replay
                      <ArrowRight size={13} />
                    </button>
                  )}
                </div>
              </div>
              {replay && (
                <div className="replay-notice">
                  <Play size={14} />
                  <span>
                    This is fabricated replay data for investigation practice.
                    It does not describe activity on your computer or measure
                    detection accuracy.
                  </span>
                </div>
              )}
              {recording && state.recording && (
                <div className="recording-notice">
                  <FileText size={15} />
                  <div>
                    <strong>Imported recording from {String(state.recording.provenance.dataset)}</strong>
                    {state.recording.provenance.revision && <p>Source revision: <code>{String(state.recording.provenance.revision)}</code></p>}
                    {state.recording.provenance.scenario_level_label && <p>{String(state.recording.provenance.scenario_level_label)}</p>}
                    <p>{state.recording.imported_events.toLocaleString()} imported events · Observed kinds: {state.recording.observed_kinds.map(eventName).join(", ")}</p>
                    <p>Recorded commands are displayed as evidence and never executed. Capture completeness is unknown; this session starts no live collection.</p>
                    {state.recording.provenance.provenance_status && <p>{String(state.recording.provenance.provenance_status)}</p>}
                    {(Array.isArray(state.recording.coverage.notes) ? state.recording.coverage.notes : []).map((note, index) => <p key={index}>{String(note)}</p>)}
                  </div>
                </div>
              )}
              {current?.ancestry_complete === false && !replay && (
                <div className="ancestry-notice">
                  <Info size={14} />
                  {recording ? "This recording is a partial capture. Process creation events, earlier ancestry and activity may be incomplete." : "This process was already running. Earlier ancestry and activity may be incomplete."}
                </div>
              )}
              <div className="metrics-grid">
                <div className="metric-card">
                  <div>
                    <span>Observed processes</span>
                    <GitBranch size={17} />
                  </div>
                  <strong>{state.processes.length.toLocaleString()}</strong>
                  <small>
                    {state.processes.filter((p) => p.ended_at).length} exited ·
                    descendants retained
                  </small>
                </div>
                <div className="metric-card">
                  <div>
                    <span>Recorded events</span>
                    <Clock3 size={17} />
                  </div>
                  <strong>{state.events.length.toLocaleString()}</strong>
                  <small>Chronological, source-linked evidence</small>
                </div>
                <div
                  className={`metric-card ${state.incidents.length ? "metric-findings" : ""}`}
                >
                  <div>
                    <span>Findings to review</span>
                    <AlertTriangle size={17} />
                  </div>
                  <strong>{state.incidents.length}</strong>
                  <small>
                    {state.incidents.length
                      ? "Select a finding to inspect its evidence"
                      : "No findings does not establish safety"}
                  </small>
                </div>
                <div className="metric-card">
                  <div>
                    <span>Telemetry coverage</span>
                    <Radio size={17} />
                  </div>
                  <strong>
                    {capabilities}
                    <em> / {state.coverage.length || "—"}</em>
                  </strong>
                  <small>
                    {state.collector.gaps?.length || 0} gaps ·{" "}
                    {state.collector.dropped_events || 0} dropped events
                  </small>
                </div>
              </div>
              <div className="investigation-grid">
                <div className="activity-column">
                  {current && <BehaviorNotesPanel
                    state={state}
                    selectedId={selectedBehaviorNoteId}
                    onSelect={(id) => {
                      setSelectedBehaviorNoteId(id);
                      setSelectedKey(null);
                      setSelectedEventId(null);
                      setFocusedIds([]);
                    }}
                    onEvidence={showEvidence}
                    onExport={() => void exportReport()}
                  />}
                  <section className="panel graph-panel">
                    <div className="panel-heading">
                      <div className="heading-with-icon">
                        <GitBranch size={17} />
                        <h2>Process relationships</h2>
                      </div>
                      <div className="graph-legend">
                        <span>
                          <i />
                          Observed relationship
                        </span>
                        <span>
                          <i className="uncertain" />
                          Uncertain
                        </span>
                      </div>
                    </div>
                    <div className="graph-canvas">
                      <ProcessGraph
                        state={state}
                        selectedKey={selectedKey}
                        onSelect={(key) => {
                          setSelectedKey(key === selectedKey ? null : key);
                          setSelectedEventId(null);
                          setFocusedIds([]);
                        }}
                      />
                      {initialLoading && (
                        <div className="graph-loading">
                          <LoaderCircle size={22} className="spin" />
                          Connecting to local collector
                        </div>
                      )}
                    </div>
                    <CoverageSummary
                      coverage={state.coverage}
                      onOpen={() => setView("settings")}
                    />
                  </section>
                  <Timeline
                    state={state}
                    selectedKey={selectedKey}
                    selectedEventId={selectedEventId}
                    focusedIds={focusedIds}
                    onEvent={(event) => setSelectedEventId(event.id)}
                    onClearFilter={clearFilter}
                  />
                </div>
                <FindingsPanel
                  state={state}
                  incidentId={selectedIncidentId}
                  onIncident={(id) => {
                    setSelectedIncidentId(id);
                    setSelectedEventId(null);
                  }}
                  onEvidence={showEvidence}
                  onExport={() => void exportReport()}
                  selectedEvent={selectedEvent}
                  onCloseEvent={() => setSelectedEventId(null)}
                  selectedProcess={selectedProcess}
                  onClearProcess={() => {
                    setSelectedKey(null);
                    setFocusedIds([]);
                  }}
                />
              </div>
            </>
          )}
          {view === "findings" && (
            <div className="findings-view">
              {state.incidents.length ? (
                <>
                  <section className="panel findings-list">
                    <div className="panel-heading">
                      <div className="heading-with-icon">
                        <AlertTriangle size={17} />
                        <h2>Session findings</h2>
                        <span className="count-pill">
                          {state.incidents.length}
                        </span>
                      </div>
                    </div>
                    {state.incidents.map((i) => (
                      <button
                        className={`finding-summary ${i.id === (selectedIncidentId || state.incidents[0]?.id) ? "active" : ""}`}
                        key={i.id}
                        onClick={() => setSelectedIncidentId(i.id)}
                      >
                        <div>
                          <Badge tone={i.severity}>{label(i.severity)}</Badge>
                          <span className="mono">
                            {typeof i.score === "number"
                              ? i.score.toFixed(3)
                              : "Rule"}
                          </span>
                        </div>
                        <h3>{i.title}</h3>
                        <p>
                          {i.event_ids.length} supporting events ·{" "}
                          {i.score_kind || "Anomaly score"}
                        </p>
                        <span>
                          Inspect finding <ArrowRight size={13} />
                        </span>
                      </button>
                    ))}
                  </section>
                  <section className="panel finding-expanded">
                    <div className="panel-heading">
                      <h2>Evidence & explanation</h2>
                      <span className="quiet-text">{current?.name}</span>
                    </div>
                    <IncidentDetail
                      incident={
                        state.incidents.find(
                          (i) => i.id === selectedIncidentId,
                        ) || state.incidents[0]
                      }
                      state={state}
                      onEvidence={showEvidence}
                      onExport={() => void exportReport()}
                    />
                  </section>
                </>
              ) : (
                <section className="panel full-empty">
                  <Empty
                    icon={FileText}
                    title="No findings in this session"
                    action={!!state.behavior_notes?.length && <button
                      className="button secondary"
                      onClick={() => {
                        setSelectedBehaviorNoteId(state.behavior_notes![0].id);
                        setView("overview");
                      }}
                    >
                      <Info size={15} />
                      View behavior notes
                    </button>}
                  >
                    Start an observation or open the investigation replay to
                    inspect evidence-linked findings. An absence of findings
                    does not establish safety. {state.behavior_notes?.length ? "This session has neutral behavior notes on Activity overview." : ""}
                  </Empty>
                </section>
              )}
            </div>
          )}
          {view === "sessions" && (
            <SessionList
              state={state}
              onSelect={selectSession}
              onDelete={(session) => {
                setDeleteTarget(session);
                setModal("delete");
                setActionError("");
              }}
              onExport={(id) => void exportReport(id)}
            />
          )}
          {view === "settings" && (
            <SettingsView
              state={state}
              busy={busy}
              onSave={saveSettings}
              onStop={() =>
                void invokeAction("stop", {}, () =>
                  setToast("All Big Brother monitoring stopped."),
                )
              }
            />
          )}
          <footer className="app-footer">
            <span>
              <Cpu size={12} />
              {state.model.name}{" "}
              <span className="mono">{state.model.version}</span>
            </span>
            <span>
              Local observation & evidence ·{" "}
              {recording ? "Imported recording" : replay ? "Replay mode" : "Windows"}
            </span>
          </footer>
        </main>
      </div>
      {toast && (
        <div className="toast" role="status">
          <Check size={16} />
          {toast}
          <button
            className="icon-button small"
            aria-label="Dismiss notification"
            onClick={() => setToast("")}
          >
            <X size={14} />
          </button>
        </div>
      )}
      {modal === "process" && (
        <ModalFrame
          title="Watch a process"
          subtitle="Choose an already-running process. Earlier activity may be incomplete."
          onClose={closeModal}
          wide
          footer={
            <>
              <span className="modal-footer-note">
                {pickerProcesses.length} running processes
              </span>
              <button className="button secondary" onClick={closeModal}>
                Cancel
              </button>
              <button
                className="button primary"
                disabled={busy || pickerPid === null}
                onClick={() =>
                  void invokeAction("watch", { pid: pickerPid }, startSession)
                }
              >
                {busy ? (
                  <LoaderCircle size={15} className="spin" />
                ) : (
                  <Activity size={15} />
                )}
                Watch selected process
              </button>
            </>
          }
        >
          <div className="picker-tools">
            <div className="search-box">
              <Search size={16} />
              <input
                aria-label="Search running processes"
                placeholder="Search by name, PID or executable path…"
                value={pickerSearch}
                onChange={(e) => setPickerSearch(e.target.value)}
                autoFocus
              />
            </div>
            <button
              className="icon-button"
              aria-label="Refresh running processes"
              onClick={() => void loadProcesses()}
              disabled={pickerLoading}
            >
              <RefreshCw size={17} className={pickerLoading ? "spin" : ""} />
            </button>
          </div>
          {actionError && (
            <div className="inline-note warning" role="alert">
              <AlertTriangle size={15} />
              {actionError}
            </div>
          )}
          <div className="process-picker-head">
            <span>Process</span>
            <span>PID</span>
            <span>Executable path</span>
          </div>
          <div className="process-picker-list">
            {pickerLoading ? (
              <div className="loading-state">
                <LoaderCircle size={22} className="spin" />
                Reading running processes…
              </div>
            ) : filteredPicker.length ? (
              filteredPicker.map((p) => (
                <button
                  className={`process-picker-row ${pickerPid === p.pid ? "selected" : ""}`}
                  key={p.pid}
                  onClick={() => setPickerPid(p.pid)}
                >
                  <span>
                    <Terminal size={17} />
                    <strong>{p.name}</strong>
                  </span>
                  <span className="mono">{p.pid}</span>
                  <span className="mono" title={p.image}>
                    {p.image || "Path unavailable"}
                  </span>
                </button>
              ))
            ) : (
              <Empty icon={Search} title="No processes found">
                {pickerSearch
                  ? "Try another process name or PID."
                  : "Refresh the list or check the collector connection."}
              </Empty>
            )}
          </div>
          <div className="inline-note">
            <Info size={15} />
            Watching records available evidence. Big Brother does not block or
            terminate the process.
          </div>
        </ModalFrame>
      )}
      {modal === "executable" && (
        <ModalFrame
          title="Launch and watch"
          subtitle="Review the selected executable before starting it."
          onClose={closeModal}
          footer={
            <>
              <button
                className="button secondary"
                disabled={busy}
                onClick={() => void chooseExecutable()}
              >
                <FolderOpen size={15} />
                Choose another
              </button>
              <button
                className="button primary"
                disabled={busy}
                onClick={() =>
                  void run(() => api().launchSelected(), startSession)
                }
              >
                {busy ? (
                  <LoaderCircle size={15} className="spin" />
                ) : (
                  <Play size={15} />
                )}
                Launch and watch
              </button>
            </>
          }
        >
          <div className="selected-executable">
            <span>
              <FileCode2 size={28} />
            </span>
            <div>
              <strong>{fileName(executablePath)}</strong>
              <p className="mono selectable">{executablePath}</p>
            </div>
          </div>
          <div className="inline-note">
            <Info size={16} />
            The file has only been selected. “Launch and watch” runs it normally
            on your computer and starts an observation session.
          </div>
          <p className="modal-body-note">
            Use programs you trust. Big Brother is an observation tool; it does
            not isolate executable behaviour.
          </p>
          {actionError && (
            <div className="inline-note warning" role="alert">
              <AlertTriangle size={15} />
              {actionError}
            </div>
          )}
        </ModalFrame>
      )}
      {modal === "replay" && (
        <ModalFrame
          title="Open a replay"
          subtitle="Explore the complete investigation workflow with fabricated recordings."
          onClose={closeModal}
          footer={
            <>
              <span className="modal-footer-note">
                No programs will be executed
              </span>
              <button className="button secondary" onClick={closeModal}>
                Cancel
              </button>
              <button
                className="button primary"
                disabled={busy}
                onClick={() =>
                  void invokeAction(
                    "replay",
                    { scenario: replayScenario },
                    startSession,
                  )
                }
              >
                {busy ? (
                  <LoaderCircle size={15} className="spin" />
                ) : (
                  <Play size={15} />
                )}
                Open replay
              </button>
            </>
          }
        >
          <div className="replay-choices">
            <button
              className={`replay-choice ${replayScenario === "investigation" ? "selected" : ""}`}
              onClick={() => setReplayScenario("investigation")}
            >
              <span className="replay-choice-icon">
                <GitBranch size={21} />
              </span>
              <div>
                <h3>Investigation</h3>
                <p>
                  An installer chain, a surviving child process, a startup
                  change and network activity.
                </p>
                <Badge tone="replay">Fabricated evidence</Badge>
              </div>
              <span className="radio-choice">
                {replayScenario === "investigation" && <span />}
              </span>
            </button>
            <button
              className={`replay-choice ${replayScenario === "ordinary" ? "selected" : ""}`}
              onClick={() => setReplayScenario("ordinary")}
            >
              <span className="replay-choice-icon">
                <Activity size={21} />
              </span>
              <div>
                <h3>Ordinary activity</h3>
                <p>
                  A short document workflow with file creation and normal termination.
                </p>
                <Badge tone="replay">Fabricated evidence</Badge>
              </div>
              <span className="radio-choice">
                {replayScenario === "ordinary" && <span />}
              </span>
            </button>
            <button
              className={`replay-choice ${replayScenario === "network" ? "selected" : ""}`}
              onClick={() => setReplayScenario("network")}
            >
              <span className="replay-choice-icon">
                <Network size={21} />
              </span>
              <div>
                <h3>Online connections</h3>
                <p>A program connects on varied ports. Inspect a neutral behavior note and its limits.</p>
                <Badge tone="replay">Fabricated evidence</Badge>
              </div>
              <span className="radio-choice">
                {replayScenario === "network" && <span />}
              </span>
            </button>
          </div>
          <div className="inline-note">
            <Info size={15} />
            Replay findings demonstrate graph reconstruction and explanations.
            They are not real-world detection results.
          </div>
          {actionError && (
            <div className="inline-note warning" role="alert">
              <AlertTriangle size={15} />
              {actionError}
            </div>
          )}
        </ModalFrame>
      )}
      {modal === "delete" && deleteTarget && (
        <ModalFrame
          title="Delete retained session?"
          subtitle="This removes locally stored evidence for this session."
          onClose={closeModal}
          footer={
            <>
              <button className="button secondary" onClick={closeModal}>
                Cancel
              </button>
              <button
                className="button danger"
                disabled={busy}
                onClick={() =>
                  void invokeAction(
                    "delete_session",
                    { session_id: deleteTarget.id },
                    () => {
                      if (selectedSessionId === deleteTarget.id) {
                        selectedSessionRef.current = undefined;
                        setSelectedSessionId(undefined);
                      }
                      setModal(null);
                      setToast("Session and retained evidence deleted.");
                    },
                  )
                }
              >
                <Trash2 size={15} />
                Delete session
              </button>
            </>
          }
        >
          <div className="delete-session-summary">
            <Terminal size={21} />
            <div>
              <strong>{deleteTarget.name}</strong>
              <p>
                {time(deleteTarget.started_at, true)} ·{" "}
                {isReplay(deleteTarget) ? "Replay" : "Live observation"}
              </p>
            </div>
          </div>
          <p className="modal-body-note">
            Its events, process graph and findings will be deleted. Export a
            report first if you need to retain them.
          </p>
          {actionError && (
            <div className="inline-note warning" role="alert">
              <AlertTriangle size={15} />
              {actionError}
            </div>
          )}
        </ModalFrame>
      )}
    </div>
  );
}
