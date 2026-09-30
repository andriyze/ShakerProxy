// Renders text as a QR code SVG using the local encoder (no network, no deps).
import { useMemo } from "react"
import { encodeQR, qrSVGPath } from "./qr"

export function QRCodeSVG({ text, size = 200, label }: { text: string; size?: number; label?: string }) {
  const code = useMemo(() => {
    try {
      return encodeQR(text, { errorCorrection: "M" })
    } catch {
      return undefined
    }
  }, [text])
  if (!code) return <p className="lgf-hint">This address is too long for a QR code; type it instead.</p>
  const border = 4
  const dimension = code.size + border * 2
  return (
    <svg className="lgf-qr" width={size} height={size} viewBox={`0 0 ${dimension} ${dimension}`} role="img" aria-label={label ?? `QR code for ${text}`} shapeRendering="crispEdges">
      <rect width={dimension} height={dimension} fill="#ffffff" />
      <path d={qrSVGPath(code, border)} fill="#000000" />
    </svg>
  )
}
