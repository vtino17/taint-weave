import type {
  DataClass,
  GraphEdge,
  GraphNode,
  SessionManifest,
} from "./types.js";

const intersects = (produces: DataClass[], consumes: DataClass[]): DataClass[] => {
  if (consumes.includes("any")) return produces.filter((item) => item !== "any");
  if (produces.includes("any")) return consumes.filter((item) => item !== "any");
  return produces.filter((item) => consumes.includes(item));
};

export const buildGraph = (manifest: SessionManifest): { nodes: GraphNode[]; edges: GraphEdge[] } => {
  const nodes = manifest.servers
    .flatMap((server) => server.tools.map((tool) => ({
      id: `${server.id}/${tool.name}`,
      serverId: server.id,
      trustZone: server.trustZone,
      tool,
    })))
    .sort((left, right) => left.id.localeCompare(right.id));
  const edges: GraphEdge[] = [];
  for (const from of nodes) {
    for (const to of nodes) {
      if (from.id === to.id) continue;
      const dataClasses = intersects(from.tool.produces, to.tool.consumes);
      if (dataClasses.length > 0) {
        edges.push({
          from: from.id,
          to: to.id,
          dataClasses: [...new Set(dataClasses)].sort(),
          crossesTrustZone: from.trustZone !== to.trustZone,
        });
      }
    }
  }
  return { nodes, edges: edges.sort((left, right) => `${left.from}:${left.to}`.localeCompare(`${right.from}:${right.to}`)) };
};

export const acceptedTaints = (taints: Set<DataClass>, consumes: DataClass[]): DataClass[] => {
  if (consumes.includes("any")) return [...taints];
  return [...taints].filter((item) => consumes.includes(item));
};
