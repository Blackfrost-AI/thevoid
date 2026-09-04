/// <reference types="vite/client" />

declare module 'react-force-graph-2d' {
  import type { ComponentType, MutableRefObject } from 'react'

  export interface ForceGraphMethods {
    zoomToFit: (ms?: number, padding?: number) => void
    centerAt: (x?: number, y?: number, ms?: number) => void
    zoom: (scale?: number, ms?: number) => void
  }

  export interface ForceGraphProps {
    ref?: MutableRefObject<ForceGraphMethods | undefined>
    graphData: { nodes: object[]; links: object[] }
    nodeId?: string
    linkSource?: string
    linkTarget?: string
    backgroundColor?: string
    linkColor?: (link: object) => string
    nodeCanvasObject?: (node: object, ctx: CanvasRenderingContext2D, globalScale: number) => void
    onNodeClick?: (node: object, event: MouseEvent) => void
    cooldownTicks?: number
    linkDirectionalArrowLength?: number
    linkDirectionalArrowRelPos?: number
  }

  const ForceGraph2D: ComponentType<ForceGraphProps>
  export type { ForceGraphMethods }
  export default ForceGraph2D
}
