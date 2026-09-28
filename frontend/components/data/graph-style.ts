/**
 * How the graph is drawn.
 *
 * Kept apart from the panel so the visual language is in one place: every node
 * type gets a distinct shape and colour, and every relation type a distinct
 * stroke. Shapes matter more than colour here, because a graph is read in
 * monochrome on a projector and by people who cannot rely on hue.
 */

export type NodeKind =
  | "application"
  | "repository"
  | "file"
  | "directory"
  | "binary"
  | "container"
  | "certificate"
  | "key"
  | "library"
  | "dependency"
  | "algorithm"
  | "api"
  | "protocol"
  | "endpoint"
  | "infrastructure"
  | "hardware"
  | "unknown";

/** Shape first, then colour: shape carries the meaning when hue cannot. */
export const NODE_STYLE: Record<
  string,
  { label: string; shape: string; color: string; group: "workload" | "material" | "package" | "primitive" | "surface" }
> = {
  application: { label: "Application", shape: "round-rectangle", color: "#3b82f6", group: "workload" },
  repository: { label: "Repository", shape: "round-rectangle", color: "#6366f1", group: "workload" },
  binary: { label: "Binary", shape: "round-rectangle", color: "#8b5cf6", group: "workload" },
  container: { label: "Container", shape: "round-rectangle", color: "#a855f7", group: "workload" },
  directory: { label: "Directory", shape: "round-rectangle", color: "#64748b", group: "workload" },
  file: { label: "File", shape: "round-rectangle", color: "#64748b", group: "workload" },
  certificate: { label: "Certificate", shape: "hexagon", color: "#f59e0b", group: "material" },
  key: { label: "Key reference", shape: "diamond", color: "#fbbf24", group: "material" },
  library: { label: "Library", shape: "rectangle", color: "#10b981", group: "package" },
  dependency: { label: "Dependency", shape: "rectangle", color: "#14b8a6", group: "package" },
  algorithm: { label: "Algorithm", shape: "ellipse", color: "#06b6d4", group: "primitive" },
  api: { label: "API", shape: "tag", color: "#ec4899", group: "surface" },
  protocol: { label: "Protocol", shape: "tag", color: "#f472b6", group: "surface" },
  endpoint: { label: "Endpoint", shape: "tag", color: "#f43f5e", group: "surface" },
  infrastructure: { label: "Infrastructure", shape: "round-diamond", color: "#0ea5e9", group: "workload" },
  hardware: { label: "Hardware", shape: "round-diamond", color: "#22d3ee", group: "material" },
  unknown: { label: "Unknown", shape: "ellipse", color: "#94a3b8", group: "primitive" }
};

export const RELATION_STYLE: Record<string, { label: string; color: string; dash: boolean; arrow: string }> = {
  contains: { label: "Contains", color: "#64748b", dash: false, arrow: "triangle" },
  uses: { label: "Uses", color: "#3b82f6", dash: false, arrow: "triangle" },
  depends_on: { label: "Depends on", color: "#10b981", dash: false, arrow: "triangle" },
  provides: { label: "Provides", color: "#14b8a6", dash: false, arrow: "triangle" },
  signed_by: { label: "Signed by", color: "#f59e0b", dash: false, arrow: "triangle" },
  exposes: { label: "Exposes", color: "#ec4899", dash: false, arrow: "triangle" },
  implements: { label: "Implements", color: "#06b6d4", dash: false, arrow: "triangle" },
  co_located: { label: "Co-located", color: "#94a3b8", dash: true, arrow: "none" },
  relates_to: { label: "Relates to", color: "#94a3b8", dash: true, arrow: "none" }
};

export const UNKNOWN_NODE = NODE_STYLE.unknown;
export const UNKNOWN_RELATION = RELATION_STYLE.relates_to;

export function nodeStyleFor(type: string) {
  return NODE_STYLE[type] || UNKNOWN_NODE;
}

export function relationStyleFor(type: string) {
  return RELATION_STYLE[type] || UNKNOWN_RELATION;
}

/** Group order, most concrete first: filters read top-down by meaning. */
export const GROUP_ORDER: Array<"workload" | "material" | "package" | "primitive" | "surface"> = [
  "workload",
  "material",
  "package",
  "primitive",
  "surface"
];

export const GROUP_LABEL: Record<string, string> = {
  workload: "Workloads",
  material: "Key material",
  package: "Packages",
  primitive: "Primitives",
  surface: "Interfaces"
};
