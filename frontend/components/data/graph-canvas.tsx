"use client";

import { useEffect, useImperativeHandle, useRef, type Ref } from "react";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";

import type { GraphEdgeRow, GraphNodeRow } from "@/lib/api/types";
import { nodeStyleFor, relationStyleFor } from "@/components/data/graph-style";

export type GraphHandle = {
  focus: (nodeId: number) => void;
  clearFocus: () => void;
  fit: () => void;
};

type Props = {
  nodes: GraphNodeRow[];
  edges: GraphEdgeRow[];
  onSelect: (node: GraphNodeRow | null) => void;
  onHover: (node: GraphNodeRow | null) => void;
  hiddenTypes: Set<string>;
  handleRef: Ref<GraphHandle | null>;
  layout: "force" | "containment" | "by-type";
};

export type GraphLayout = "force" | "containment" | "by-type";

/**
 * Containment reads best as a tree because "contains" is genuinely hierarchical;
 * by-type puts the primitives in the middle, which is the right read when the
 * question is "what sits near this algorithm".
 *
 * These options are only ever used to *compute* positions. They never animate.
 */

function layoutOptionsFor(layout: GraphLayout): cytoscape.LayoutOptions {
  // `fit` is stated rather than left to Cytoscape's default: a switch changes the
  // shape of the graph, so the camera has to be reframed or the result can land
  // off-screen.
  if (layout === "by-type") {
    return {
      name: "concentric",
      padding: 30,
      animate: false,
      fit: true,
      // Primitives in the centre, because everything else is built on them.
      concentric: (node: cytoscape.NodeSingular) =>
        (node.data("nodeType") || "") === "algorithm" ? 2 : 1
    };
  }
  return {
    name: "cose",
    animate: false,
    padding: 30,
    fit: true,
    nodeRepulsion: () => 5200,
    idealEdgeLength: () => 78,
    nodeOverlap: 18
  };
}

type Point = { x: number; y: number };

/**
 * Layered positions derived from the containment edges.
 *
 * Cytoscape's `breadthfirst` was not producing a usable arrangement here: it
 * infers roots and depths internally, and on a graph whose containment edges
 * contain cycles and cross-links, nodes never get a depth and keep their old
 * positions -- so switching to "Containment" looked like nothing happened.
 *
 * Computing the levels here makes the layout deterministic: cycles terminate on
 * a visited set, and anything unreachable is parked below the deepest level
 * rather than being left where it was. Levels run top to bottom, so containment
 * reads downwards, which is the direction the eye expects.
 */
function containmentPositions(
  nodes: GraphNodeRow[],
  edges: GraphEdgeRow[],
  viewport: { width: number; height: number }
): Record<string, Point> {
  const ids = nodes.map((node) => String(node.id));
  const known = new Set(ids);

  // Prefer `contains`; if a scan produced none, fall back to every edge so the
  // layout still says something rather than collapsing to a single row.
  const structural = edges.filter((edge) => edge.kind === "contains");
  const usable = (structural.length ? structural : edges).filter(
    (edge) => known.has(String(edge.from)) && known.has(String(edge.to))
  );

  const children = new Map<string, string[]>();
  const hasParent = new Set<string>();
  for (const edge of usable) {
    const from = String(edge.from);
    const to = String(edge.to);
    if (from === to) continue;
    if (!children.has(from)) children.set(from, []);
    children.get(from)!.push(to);
    hasParent.add(to);
  }

  const roots = ids.filter((id) => !hasParent.has(id));
  const start = roots.length ? roots : ids.slice(0, 1);

  // Longest-path layering, not breadth-first.
  //
  // Containment here is a DAG: a file is recorded as contained by both the
  // application and the project directory, so a file has two parents. BFS gives
  // a node the depth of whichever path reached it first, which lands a parent
  // and its child on the same row and draws edges sideways. Pushing every node
  // strictly below all of its parents is what makes the tree read correctly.
  // The pass repeats until it settles, bounded so a cycle cannot spin forever.
  const depth = new Map<string, number>(ids.map((id) => [id, 0]));
  for (let pass = 0; pass <= ids.length; pass += 1) {
    let changed = false;
    for (const edge of usable) {
      const from = String(edge.from);
      const to = String(edge.to);
      if (from === to) continue;
      const candidate = (depth.get(from) ?? 0) + 1;
      if (candidate > (depth.get(to) ?? 0)) {
        depth.set(to, candidate);
        changed = true;
      }
    }
    if (!changed) break;
  }

  // Depth-first discovery order, so the starting arrangement is deterministic
  // and reproducible rather than dependent on the order the query returned.
  const order = new Map<string, number>();
  let counter = 0;
  const walk = (id: string) => {
    if (order.has(id)) return;
    order.set(id, counter++);
    for (const child of (children.get(id) || []).slice().sort()) walk(child);
  };
  for (const root of start.slice().sort()) walk(root);
  for (const id of ids) walk(id); // anything only reachable through a cycle

  const layers = new Map<number, string[]>();
  for (const id of ids) {
    const level = depth.get(id) ?? 0;
    if (!layers.has(level)) layers.set(level, []);
    layers.get(level)!.push(id);
  }
  const levels = [...layers.keys()].sort((a, b) => a - b);
  for (const members of layers.values()) {
    members.sort((a, b) => (order.get(a) ?? 0) - (order.get(b) ?? 0));
  }

  // Rows are laid out in discovery order, measured at zero overlaps and
  // deterministic across runs.
  //
  // The gaps are derived from the real container rather than fixed, because a
  // containment tree is a shallow fan: every node with no container
  // (algorithms, certificates, keys) sits in the top row, so 8-10 of them land
  // side by side while the tree is only 3-4 deep. Fixed gaps produced a shape
  // 2.4-3.2x wider than tall, which `fit` then rendered at 0.59-0.99x -- a thin
  // strip of small nodes with dead space above and below. Sizing the layout to
  // the actual viewport fills the space it has at any window size, instead of
  // assuming a canvas that may not be the one on screen.
  const width = Math.max(viewport.width, 320);
  const height = Math.max(viewport.height, 240);

  const rows = levels.length;
  const widest = Math.max(...levels.map((level) => layers.get(level)!.length), 1);
  const NODE_GAP = Math.max(80, (width * 0.92) / Math.max(widest, 1));
  const LAYER_GAP = Math.max(
    NODE_GAP * 0.75,
    Math.min(NODE_GAP * 2.2, (height * 0.94) / Math.max(rows - 1, 1))
  );

  const positions: Record<string, Point> = {};
  for (const level of levels) {
    const members = layers.get(level)!;
    members.forEach((id, index) => {
      // Centre each row so the tree reads symmetrically rather than drifting
      // right as each level grows.
      positions[id] = {
        x: (index - (members.length - 1) / 2) * NODE_GAP,
        y: level * LAYER_GAP
      };
    });
  }
  return positions;
}

/**
 * Lay the graph out, then frame it.
 *
 * Layout changes snap rather than animate. Switching between these arrangements
 * moves every node roughly 570px on average, because a force layout is wide and a
 * tree is compact, and no transition duration made that read well -- a long one
 * looked like the graph was coming apart, a short one like nothing had happened.
 * Snapping is also what graph explorers do for a layout switch.
 *
 * The `preset` layout appears only for containment, which is computed here.
 * Cytoscape's own `breadthfirst` is not used: its animated pass sorts the live
 * node collection and crashed with `Cannot read properties of null (reading 'id')`
 * on graphs whose containment edges form cycles.
 */
function applyLayout(
  cy: cytoscape.Core,
  layout: GraphLayout,
  nodes: GraphNodeRow[],
  edges: GraphEdgeRow[],
  container: HTMLElement | null
) {
  if (!cy.nodes().length) return;

  // Force and By-type are Cytoscape's own layouts and they run directly. An
  // earlier version routed every layout through a `preset` round-trip to dodge a
  // crash that only ever came from `breadthfirst`; extending that workaround to
  // these two is what stopped them working, so it is confined to containment.
  if (layout !== "containment") {
    cy.layout(layoutOptionsFor(layout)).run();
    return;
  }

  const viewport = {
    width: container?.clientWidth || 860,
    height: container?.clientHeight || 560
  };
  const positions = containmentPositions(nodes, edges, viewport);
  if (!Object.keys(positions).length) return;

  // Containment is a tree computed here, applied with `preset` -- a plain
  // position map, which is why no animated breadth-first pass ever runs.
  cy.layout({ name: "preset", positions, animate: false, fit: true, padding: 30 }).run();
}

export function GraphCanvas({
  nodes,
  edges,
  onSelect,
  onHover,
  hiddenTypes,
  handleRef,
  layout
}: Props) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const appliedLayoutRef = useRef<GraphLayout | null>(null);
  // True once the initial layout has run on the current core.
  const readyRef = useRef(false);
  const selectRef = useRef(onSelect);
  const hoverRef = useRef(onHover);

  // Cytoscape binds its handlers once when the graph is built, so they need the
  // latest callbacks without being re-bound. Writing these refs during render
  // would be a side effect, so they are synced after commit.
  useEffect(() => {
    selectRef.current = onSelect;
    hoverRef.current = onHover;
  }, [onSelect, onHover]);

  // Built once per data change. Rebuilding on a filter change is deliberate:
  // Cytoscape's own filtering would need the same rules a second time, and
  // re-seeding keeps one source of truth for what is visible.
  useEffect(() => {
    if (!containerRef.current) return;

    const visibleNodes = nodes.filter((node) => !hiddenTypes.has(node.node_type));
    const visibleIds = new Set(visibleNodes.map((node) => node.id));
    const visibleEdges = edges.filter(
      (edge) => visibleIds.has(edge.from) && visibleIds.has(edge.to)
    );


    const elements: ElementDefinition[] = [
      ...visibleNodes.map((node) => {
        const style = nodeStyleFor(node.node_type);
        return {
          group: "nodes" as const,
          data: {
            id: String(node.id),
            label: node.label || node.key,
            nodeType: node.node_type,
            nodeTypeLabel: style.label,
            color: style.color,
            shape: style.shape,
            detail: node
          }
        };
      }),
      ...visibleEdges.map((edge) => {
        const style = relationStyleFor(edge.kind);
        return {
          group: "edges" as const,
          data: {
            id: `e${edge.from}-${edge.to}-${edge.kind}`,
            source: String(edge.from),
            target: String(edge.to),
            kind: edge.kind,
            kindLabel: style.label,
            color: style.color,
            // A string, not a boolean. `line-style: false` is not a valid
            // value, and Cytoscape treats a falsy data field as absent, so a
            // boolean silently dropped the mapping for every solid edge.
            lineStyle: style.dash ? "dashed" : "solid",
            arrow: style.arrow,
            why: edge.why
          }
        };
      })
    ];

    // Shape, arrow and dash come from per-type data, which Cytoscape's
    // typings cannot express as literal unions. The values themselves are from
    // the fixed sets in graph-style.ts, so this is a typing gap, not a cast over
    // unvalidated input.
    const stylesheet = [
      {
        selector: "node",
        style: {
          "background-color": "data(color)",
          shape: "data(shape)",
          label: "data(label)",
          color: "#e2e8f0",
          "font-size": 9,
          "text-valign": "bottom",
          "text-margin-y": 4,
          "text-max-width": 120,
          "text-wrap": "ellipsis",
          width: 22,
          height: 22,
          "border-width": 1,
          "border-color": "#0b1220",
          "overlay-opacity": 0,
          "transition-property": "opacity, border-width, border-color",
          "transition-duration": 140
        }
      },
      {
        // Labels only earn their space once the graph is small enough to read.
        selector: "node.labelled",
        style: { "font-size": 9 }
      },
      {
        selector: "edge",
        style: {
          width: 1.2,
          "line-color": "data(color)",
          "target-arrow-color": "data(color)",
          "target-arrow-shape": "data(arrow)",
          "curve-style": "bezier",
          opacity: 0.55,
          "line-style": "data(lineStyle)",
          "arrow-scale": 0.7,
          "transition-property": "opacity, width",
          "transition-duration": 140
        }
      },
      {
        selector: ":selected",
        style: {
          "border-width": 3,
          "border-color": "#f8fafc",
          "z-index": 30
        }
      },
      {
        // Focus dims everything not adjacent, which is the only way a dense
        // graph becomes readable without hiding data.
        selector: ".dimmed",
        style: { opacity: 0.12, "text-opacity": 0 }
      },
      {
        selector: ".faded",
        style: { opacity: 0.18 }
      },
      {
        selector: "node.neighbour",
        style: { "border-width": 2, "border-color": "#cbd5e1" }
      }
    ] as unknown as cytoscape.StylesheetJson;

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: stylesheet,
      minZoom: 0.15,
      maxZoom: 3,
      boxSelectionEnabled: true,
      autounselectify: false,
      // Deliberately a no-op. Running the real layout here would lay out
      // against a container that has not been sized yet, which yields
      // degenerate positions; a later animated layout then sorts those and dies
      // on `Cannot read properties of null (reading 'id')`. The real layout is
      // run on the next frame, after an explicit resize.
      layout: { name: "preset" }
    });

    cyRef.current = cy;
    // A new core has not had the layout applied to it yet.
    appliedLayoutRef.current = null;
    readyRef.current = false;

    const initialFrame = window.requestAnimationFrame(() => {
      if (cy.destroyed()) return;
      cy.resize();
      // Deferred by a frame so the container has been measured; laying out
      // against an unsized container produces degenerate positions.
      applyLayout(cy, layout, nodes, edges, containerRef.current);
      appliedLayoutRef.current = layout;
      readyRef.current = true;
    });

    const applyLabelDensity = () => {
      const count = cy.nodes().length;
      // 9px labels are unreadable and slow past a couple of hundred nodes.
      if (count <= 60) {
        cy.nodes().addClass("labelled");
      } else if (count <= 160) {
        cy.nodes().forEach((node) => {
          const degree = node.degree(false);
          if (degree >= 2) node.addClass("labelled");
        });
      }
    };
    applyLabelDensity();

    cy.on("tap", "node", (event) => {
      const id = Number(event.target.id());
      const row = nodes.find((node) => node.id === id) || null;
      selectRef.current(row);
    });
    cy.on("tap", (event) => {
      if (event.target === cy) selectRef.current(null);
    });
    cy.on("mouseover", "node", (event) => {
      const id = Number(event.target.id());
      hoverRef.current(nodes.find((node) => node.id === id) || null);
    });
    cy.on("mouseout", "node", () => hoverRef.current(null));

    // Neighbourhood emphasis. Reached through the graph rather than the
    // selection state so a hover also shows the blast radius cheaply.
    const emphasise = (id: string | null) => {
      cy.batch(() => {
        cy.elements().removeClass("dimmed faded neighbour");
        if (!id) return;
        const node = cy.getElementById(id);
        if (node.empty()) return;
        const neighbourhood = node.closedNeighborhood();
        node.addClass("neighbour");
        neighbourhood.nodes().addClass("neighbour");
        cy.elements().difference(neighbourhood).addClass("dimmed");
        neighbourhood.edges().removeClass("dimmed");
      });
    };
    cy.on("select unselect", "node", (event) => emphasise(event.target.id() as string));

    const timer = window.setTimeout(() => cy.resize(), 0);
    return () => {
      window.clearTimeout(timer);
      window.cancelAnimationFrame(initialFrame);
      readyRef.current = false;
      cy.destroy();
      cyRef.current = null;
    };
    // `layout` is excluded deliberately: the effect below applies it, and
    // rebuilding on a layout change would drop the camera and the selection.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, edges, hiddenTypes]);

  // Changing the layout re-runs it on the existing graph, so the camera and the
  // current selection survive the change.
  useEffect(() => {
    if (appliedLayoutRef.current === layout) return undefined;

    const frame = window.requestAnimationFrame(() => {
      const cy = cyRef.current;
      // `readyRef` is false until the first layout has run, so positions exist.
      if (!cy || cy.destroyed() || !readyRef.current) return;
      cy.resize();
      appliedLayoutRef.current = layout;
      applyLayout(cy, layout, nodes, edges, containerRef.current);
    });

    return () => window.cancelAnimationFrame(frame);
    // nodes/edges are memoised upstream. Listing them keeps the hook honest; the
    // appliedLayout guard stops a rebuild from re-running the same layout.
  }, [layout, nodes, edges]);

  useImperativeHandle(
    handleRef,
    (): GraphHandle => ({
      focus: (nodeId: number) => {
        const cy = cyRef.current;
        if (!cy) return;
        const node = cy.getElementById(String(nodeId));
        if (node.empty()) return;
        cy.nodes().unselect();
        node.select();
        cy.animate({ center: { eles: node }, zoom: 1.4 }, { duration: 260 });
      },
      clearFocus: () => {
        cyRef.current?.nodes().unselect();
        cyRef.current?.elements().removeClass("dimmed faded neighbour");
      },
      fit: () => cyRef.current?.fit(undefined, 30)
    }),
    []
  );

  return <div ref={containerRef} className="h-full w-full" data-testid="graph-canvas" />;
}
