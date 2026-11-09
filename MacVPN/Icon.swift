import AppKit
import CoreGraphics

let size = 1024
let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!
let context = CGContext(
    data: nil, width: size, height: size, bitsPerComponent: 8,
    bytesPerRow: size * 4, space: colorSpace,
    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
)!
context.translateBy(x: 0, y: CGFloat(size))
context.scaleBy(x: 1, y: -1)

func color(_ hex: Int, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat((hex >> 16) & 255) / 255,
            green: CGFloat((hex >> 8) & 255) / 255,
            blue: CGFloat(hex & 255) / 255, alpha: alpha)
}

func rounded(_ rect: CGRect, _ radius: CGFloat, _ fill: Int) {
    context.addPath(CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil))
    context.setFillColor(color(fill))
    context.fillPath()
}

func circle(_ x: CGFloat, _ y: CGFloat, _ radius: CGFloat, _ fill: CGColor) {
    context.setFillColor(fill)
    context.fillEllipse(in: CGRect(x: x - radius, y: y - radius, width: radius * 2, height: radius * 2))
}

let tile = CGRect(x: 72, y: 72, width: 880, height: 880)
rounded(tile, 188, 0x101117)
context.saveGState()
context.addPath(CGPath(roundedRect: tile, cornerWidth: 188, cornerHeight: 188, transform: nil))
context.clip()
let halo = CGGradient(colorsSpace: colorSpace, colors: [color(0x38303A), color(0x101117)] as CFArray, locations: [0, 1])!
context.drawRadialGradient(
    halo, startCenter: CGPoint(x: 450, y: 365), startRadius: 0,
    endCenter: CGPoint(x: 450, y: 365), endRadius: 650, options: [.drawsAfterEndLocation]
)

context.saveGState()
context.translateBy(x: 508, y: 533)
context.rotate(by: -.pi / 7)
context.setStrokeColor(color(0xFFAB75, 0.55))
context.setLineWidth(13)
context.strokeEllipse(in: CGRect(x: -365, y: -132, width: 730, height: 264))
context.restoreGState()
circle(800, 342, 26, color(0xFFAB75))
circle(236, 277, 10, color(0xFAE9DF, 0.80))
circle(748, 734, 9, color(0xFAE9DF, 0.60))
circle(195, 674, 6, color(0xFAE9DF, 0.50))

rounded(CGRect(x: 360, y: 660, width: 304, height: 112), 54, 0xDFC7B9)
rounded(CGRect(x: 300, y: 471, width: 82, height: 118), 32, 0xDAB4A0)
rounded(CGRect(x: 642, y: 471, width: 82, height: 118), 32, 0xDAB4A0)
rounded(CGRect(x: 330, y: 316, width: 364, height: 407), 171, 0xF8EAE0)
rounded(CGRect(x: 365, y: 436, width: 294, height: 212), 85, 0x26222E)
rounded(CGRect(x: 383, y: 452, width: 258, height: 181), 72, 0x141720)
context.setStrokeColor(color(0xFFAB75, 0.78))
context.setLineWidth(13)
context.setLineCap(.round)
context.move(to: CGPoint(x: 421, y: 526))
context.addQuadCurve(to: CGPoint(x: 500, y: 481), control: CGPoint(x: 443, y: 489))
context.strokePath()
circle(594, 573, 9, color(0xF8EAE0, 0.75))
circle(569, 598, 5, color(0xF8EAE0, 0.45))
rounded(CGRect(x: 479, y: 693, width: 66, height: 14), 7, 0xD19578)
context.restoreGState()

let image = NSBitmapImageRep(cgImage: context.makeImage()!)
try image.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
