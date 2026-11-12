import AppKit
import CoreGraphics

let iconURL = URL(fileURLWithPath: CommandLine.arguments[1])
let output = URL(fileURLWithPath: CommandLine.arguments[2])
let image = NSImage(size: NSSize(width: 320, height: 180))
image.lockFocus()
NSColor(red: 0.055, green: 0.06, blue: 0.075, alpha: 1).setFill()
NSBezierPath(rect: NSRect(x: 0, y: 0, width: 320, height: 180)).fill()
let icon = NSImage(contentsOf: iconURL)!
icon.draw(in: NSRect(x: 20, y: 48, width: 84, height: 84))
let font = NSFont.systemFont(ofSize: 27, weight: .bold)
let text = NSAttributedString(string: "Qosmos VPN", attributes: [
    .font: font,
    .foregroundColor: NSColor(red: 0.98, green: 0.96, blue: 0.93, alpha: 1),
])
text.draw(at: NSPoint(x: 110, y: 74))
image.unlockFocus()
let bitmap = NSBitmapImageRep(data: image.tiffRepresentation!)!
try bitmap.representation(using: .png, properties: [:])!.write(to: output)
