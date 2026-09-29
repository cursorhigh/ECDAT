/**
 * How the graph is drawn.
 *
 * Kept apart from the panel so the visual language is in one place: every node
 * type gets a distinct shape and colour, and every relation type a distinct
 * stroke. Shapes matter more than colour here, because a graph is read in
 * monochrome on a projector and by people who cannot rely on hue.
 *
 * Palette notes
 * -------------
 * The previous set was the stock Tailwind 500 ramp used at full saturation --
 * every hue equally loud, so nothing read as more important than anything else
 * and the graph looked like a wall of stickers. This set is grouped by meaning
 * and held at a similar chroma and lightness within each group, so a cluster of
 * the same kind of thing looks like a family and the eye can find the outliers.
 * The two "high-attention" hues (certificate amber, endpoint rose) are kept
 * apart so a real finding stands out from routine structure.
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
  // Workloads: indigo/violet family, rounded rectangles.
  application: { label: "Application", shape: "round-rectangle", color: "#5b6ee1", group: "workload" },
  repository: { label: "Repository", shape: "round-rectangle", color: "#7a6ff0", group: "workload" },
  binary: { label: "Binary", shape: "round-rectangle", color: "#8f6ae8", group: "workload" },
  container: { label: "Container", shape: "round-rectangle", color: "#6d7ce0", group: "workload" },
  directory: { label: "Directory", shape: "round-rectangle", color: "#8a90a6", group: "workload" },
  file: { label: "File", shape: "round-rectangle", color: "#9aa0b4", group: "workload" },
  infrastructure: { label: "Infrastructure", shape: "round-diamond", color: "#4f7fd4", group: "workload" },

  // Key material: warm gold, and the two shapes that say "credential".
  certificate: { label: "Certificate", shape: "hexagon", color: "#d99a2b", group: "material" },
  key: { label: "Key reference", shape: "round-diamond", color: "#e0b34a", group: "material" },
  hardware: { label: "Hardware", shape: "round-diamond", color: "#c98f5c", group: "material" },

  // Packages: cool green, flat rectangles.
  library: { label: "Library", shape: "rectangle", color: "#3f9e7a", group: "package" },
  dependency: { label: "Dependency", shape: "rectangle", color: "#4f8f96", group: "package" },

  // Primitives: cyan, ellipses.
  algorithm: { label: "Algorithm", shape: "ellipse", color: "#4a9bb5", group: "primitive" },
  unknown: { label: "Unknown", shape: "ellipse", color: "#9aa0b4", group: "primitive" },

  // Interfaces: rose, rounded tags.
  api: { label: "API", shape: "round-tag", color: "#c2619a", group: "surface" },
  protocol: { label: "Protocol", shape: "round-tag", color: "#b06fae", group: "surface" },
  endpoint: { label: "Endpoint", shape: "round-tag", color: "#cf5f6b", group: "surface" }
};

export const RELATION_STYLE: Record<string, { label: string; color: string; dash: boolean; arrow: string }> = {
  contains: { label: "Contains", color: "#7b8296", dash: false, arrow: "vee" },
  uses: { label: "Uses", color: "#5b6ee1", dash: false, arrow: "vee" },
  depends_on: { label: "Depends on", color: "#3f9e7a", dash: false, arrow: "vee" },
  provides: { label: "Provides", color: "#4f8f96", dash: false, arrow: "vee" },
  signed_by: { label: "Signed by", color: "#d99a2b", dash: false, arrow: "vee" },
  exposes: { label: "Exposes", color: "#c2619a", dash: false, arrow: "vee" },
  implements: { label: "Implements", color: "#4a9bb5", dash: false, arrow: "vee" },
  co_located: { label: "Co-located", color: "#9aa0b4", dash: true, arrow: "none" },
  relates_to: { label: "Relates to", color: "#9aa0b4", dash: true, arrow: "none" }
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
