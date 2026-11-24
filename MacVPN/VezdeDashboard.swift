import SwiftUI

struct VezdeDashboard: View {
    @ObservedObject var model: VPNModel
    @ObservedObject var preferences: AppPreferences
    var openSubscription: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var showingCountries = false

    private let ink = VezdeLayout.ink
    private let muted = VezdeLayout.muted
    private let mint = VezdeLayout.mint
    private var highlighted: Bool { model.state == .connected }
    private var automatic: Bool { model.voxCountry == VPNModel.automaticCountry }
    private var panel: Color { VezdeLayout.panel(connected: highlighted) }

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            header
            hero
            if model.voxActivated {
                connectionButton
                countryPicker
                protocolPicker
                statistics
            } else {
                activationButton
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 16)
        .frame(width: VezdeLayout.width)
        .background(VezdeLayout.background(connected: highlighted))
        .foregroundStyle(ink)
        .tint(mint)
        .animation(reduceMotion ? nil : .easeOut(duration: 0.28), value: highlighted)
        .onAppear {
            if model.voxActivated && model.voxCountries.isEmpty { model.loadVoxCountries() }
            model.refreshVoxUsage()
        }
        .task(id: highlighted) {
            guard highlighted else { return }
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: 60_000_000_000) }
                catch { return }
                model.refreshVoxUsage()
            }
        }
    }

    private var header: some View {
        HStack(spacing: 8) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 34, height: 34)
                .saturation(highlighted ? 1 : 0)
                .accessibilityHidden(true)
            Text("Vezde VPN")
                .font(.system(size: 24, weight: .bold, design: .rounded))
                .tracking(-1.1)
            Spacer()
            headerButton("person.crop.circle", title: "Профиль", action: openSubscription)
            headerButton("gearshape", title: "Настройки") {
                preferences.refreshLoginStatus()
                model.showSettings = true
            }
        }
    }

    private func headerButton(_ icon: String, title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: icon)
                .font(.system(size: 16, weight: .medium))
                .frame(width: 35, height: 35)
                .background(.white.opacity(0.055), in: RoundedRectangle(cornerRadius: 9))
        }
        .buttonStyle(VezdePress())
        .accessibilityLabel(preferences.text(title))
        .help(preferences.text(title))
    }

    private var hero: some View {
        ZStack(alignment: .bottomLeading) {
            VezdeOrbitArt()
                .saturation(highlighted ? 1 : 0)
                .accessibilityHidden(true)
            LinearGradient(stops: [
                .init(color: .clear, location: 0.37),
                .init(color: highlighted ? Color(red: 0.031, green: 0.089, blue: 0.073) : Color(white: 0.077),
                      location: 1)
            ], startPoint: .top, endPoint: .bottom)
            VStack(alignment: .leading, spacing: 7) {
                if highlighted, let exitIP = model.exitIP {
                    HStack(spacing: 7) {
                        Circle().fill(mint).frame(width: 7, height: 7)
                            .accessibilityHidden(true)
                        Text(exitIP)
                            .font(.system(size: 12, weight: .semibold, design: .monospaced))
                            .foregroundStyle(mint)
                            .textSelection(.enabled)
                            .accessibilityLabel(preferences.text("IP выхода VPN") + " " + exitIP)
                        if let activeProtocol = model.connectedVoxProtocol {
                            Text(activeProtocol.label)
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundStyle(mint)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(mint.opacity(0.12), in: Capsule())
                                .accessibilityLabel(preferences.text("Активный протокол") + " " + activeProtocol.label)
                        }
                    }
                }
                Text(preferences.text(model.stateLabel))
                    .font(.system(size: 37, weight: .bold, design: .rounded))
                    .tracking(-1.5)
                    .lineLimit(2)
                    .minimumScaleFactor(0.75)
                if model.isIdle && model.tunnelInUse {
                    Text(preferences.text(model.detail))
                        .font(.system(size: 12))
                        .foregroundStyle(muted)
                    Button(preferences.text("Обновить статус")) {
                        model.refreshTerminal(refreshIP: true)
                    }
                    .buttonStyle(.link)
                } else if model.isIdle && model.internetBlocked {
                    Text(preferences.text(model.detail))
                        .font(.system(size: 12))
                        .foregroundStyle(muted)
                    Button(preferences.text("Вернуть доступ"), action: model.restoreInternet)
                        .buttonStyle(.link)
                } else if model.voxActivated && !["Системный VPN активен.", "VPN отключён."].contains(model.detail) {
                    Text(preferences.text(model.detail))
                        .font(.system(size: 12))
                        .foregroundStyle(muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
        }
        .frame(height: 230)
        .clipShape(RoundedRectangle(cornerRadius: 22))
        .overlay(RoundedRectangle(cornerRadius: 22).strokeBorder(.white.opacity(0.12)))
    }

    private var connectionButton: some View {
        let busy = model.state == .connecting || model.state == .reconnecting
        return Button(action: model.toggleConnection) {
            HStack(spacing: 10) {
                if busy {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "power")
                        .font(.system(size: 16, weight: .semibold))
                }
                Text(preferences.text(model.actionLabel))
                    .font(.system(size: 15, weight: .bold))
            }
            .frame(maxWidth: .infinity, minHeight: 51)
            .foregroundStyle(highlighted ? mint : Color(white: 0.08))
            .background(
                highlighted ? Color(red: 0.15, green: 0.28, blue: 0.22) : Color(white: 0.84),
                in: RoundedRectangle(cornerRadius: 11)
            )
        }
        .buttonStyle(VezdePress())
        .disabled(!model.canToggle)
    }

    private var activationButton: some View {
        Button(action: openSubscription) {
            Label(preferences.text("Активировать подписку"), systemImage: "key")
                .font(.system(size: 15, weight: .bold))
                .frame(maxWidth: .infinity, minHeight: 51)
                .foregroundStyle(Color(white: 0.08))
                .background(Color(white: 0.84), in: RoundedRectangle(cornerRadius: 11))
        }
        .buttonStyle(VezdePress())
        .disabled(!model.voxAvailable)
    }

    private var selectedCountry: String {
        if automatic { return preferences.text("Авто") }
        return countryName(model.voxCountry) ?? preferences.text("Выбрать страну")
    }

    private func countryName(_ code: String?) -> String? {
        guard let code else { return nil }
        return model.voxCountries.first { $0.code == code }?.label(language: preferences.language)
            ?? Locale(identifier: preferences.language.rawValue).localizedString(forRegionCode: code)
    }

    private var countryPicker: some View {
        Button {
            showingCountries = true
            if model.voxCountries.isEmpty { model.loadVoxCountries() }
        } label: {
            HStack(spacing: 12) {
                VStack { routeIcon(model.voxCountry, automatic: automatic) }
                    .frame(width: 36, height: 36)
                    .background(.white.opacity(0.075), in: RoundedRectangle(cornerRadius: 9))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text(preferences.text("Локация"))
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(muted)
                    Text(selectedCountry)
                        .font(.system(size: 16, weight: .semibold))
                }
                Spacer(minLength: 8)
                if automatic && highlighted, let active = countryName(model.connectedVoxCountry) {
                    Text(active)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(mint)
                        .lineLimit(1)
                }
                Image(systemName: "chevron.up.chevron.down")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(muted)
                    .accessibilityHidden(true)
            }
            .padding(.vertical, 10)
            .padding(.horizontal, 12)
            .background(panel, in: RoundedRectangle(cornerRadius: 13))
        }
        .buttonStyle(VezdePress(dimWhenDisabled: false))
        .disabled(!model.isIdle)
        .help(preferences.text(model.isIdle ? "Выбрать страну" : "Отключите VPN, чтобы сменить страну."))
        .popover(isPresented: $showingCountries, arrowEdge: .bottom) {
            VezdeCountryPicker(model: model, preferences: preferences) { code in
                model.chooseVoxCountry(code)
                showingCountries = false
            }
        }
    }

    private var protocolPicker: some View {
        HStack(spacing: 10) {
            Label(preferences.text("Протокол"), systemImage: "network")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(muted)
            Spacer()
            Menu {
                ForEach(VoxProtocol.allCases) { choice in
                    Button {
                        model.chooseVoxProtocol(choice)
                    } label: {
                        if model.voxProtocol == choice {
                            Label(choice.label, systemImage: "checkmark")
                        } else {
                            Text(choice.label)
                        }
                    }
                    .disabled(!model.canChooseVoxProtocol(choice))
                }
            } label: {
                Text(model.voxProtocol.label)
                    .font(.system(size: 13, weight: .semibold))
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .accessibilityLabel(preferences.text("Протокол") + " " + model.voxProtocol.label)
            .disabled(!model.isIdle)
            .help(preferences.text(model.isIdle ? "Выбрать протокол" : "Отключите VPN, чтобы сменить протокол."))
        }
        .padding(.vertical, 8)
        .padding(.horizontal, 12)
        .background(panel, in: RoundedRectangle(cornerRadius: 13))
    }

    private var statistics: some View {
        HStack(alignment: .top, spacing: 17) {
            metric("Устройства", icon: "laptopcomputer.and.iphone",
                   value: model.voxUsage.map { "\($0.devicesUsed) / \($0.deviceLimit)" } ?? "—")
                .help(preferences.text("Использованные устройства и лимит подписки"))
            Rectangle().fill(.white.opacity(0.1)).frame(width: 1, height: 42)
                .accessibilityHidden(true)
            metric("Трафик за месяц", icon: "arrow.up.arrow.down",
                   value: model.voxUsage.map { ByteCountFormatter.string(fromByteCount: $0.monthlyBytes, countStyle: .decimal) } ?? "—")
            if model.voxUsageUnavailable {
                Button { model.refreshVoxUsage() } label: {
                    Image(systemName: "arrow.clockwise")
                        .frame(width: 24, height: 28)
                }
                .buttonStyle(VezdePress())
                .accessibilityLabel(preferences.text("Обновить данные подписки"))
                .help(preferences.text("Данные подписки недоступны. Обновить."))
            }
        }
        .padding(13)
        .background(panel, in: RoundedRectangle(cornerRadius: 13))
    }

    private func metric(_ title: String, icon: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(preferences.text(title), systemImage: icon)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(muted)
                .lineLimit(1)
            Text(value)
                .font(.system(size: 19, weight: .semibold, design: .rounded))
                .monospacedDigit()
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}

private struct VezdeCountryPicker: View {
    @ObservedObject var model: VPNModel
    @ObservedObject var preferences: AppPreferences
    var choose: (String) -> Void

    @State private var filter = ""
    @FocusState private var searchFocused: Bool

    private var countries: [VoxCountry] {
        let query = filter.trimmingCharacters(in: .whitespacesAndNewlines)
        return model.voxCountriesForProtocol.filter {
            query.isEmpty || $0.label(language: preferences.language).localizedStandardContains(query)
                || $0.name.localizedStandardContains(query) || $0.code.localizedStandardContains(query)
        }.sorted {
            $0.label(language: preferences.language).localizedStandardCompare($1.label(language: preferences.language))
                == .orderedAscending
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack {
                Text(preferences.text("Выбрать страну"))
                    .font(.system(size: 18, weight: .semibold, design: .rounded))
                Spacer()
                Button { model.loadVoxCountries() } label: {
                    Image(systemName: "arrow.clockwise").frame(width: 24, height: 24)
                }
                .buttonStyle(VezdePress())
                .accessibilityLabel(preferences.text("Обновить список стран"))
                .disabled(model.voxBusy)
            }
            HStack(spacing: 7) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                TextField(preferences.text("Поиск страны"), text: $filter)
                    .textFieldStyle(.plain)
                    .focused($searchFocused)
            }
            .padding(9)
            .background(.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 8))
            row(VPNModel.automaticCountry, name: preferences.text("Авто"),
                detail: preferences.text("Подбирает рабочую локацию"))
            Divider()
            if countries.isEmpty {
                if model.voxBusy {
                    ProgressView().controlSize(.small)
                        .frame(maxWidth: .infinity, minHeight: 55)
                } else {
                    Text(preferences.text(filter.isEmpty ? "Страны пока недоступны" : "Страны не найдены"))
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 9)
                }
            } else {
                ScrollView {
                    LazyVStack(spacing: 2) {
                        ForEach(countries) { country in
                            row(country.code, name: country.label(language: preferences.language))
                        }
                    }
                }
                .frame(height: min(CGFloat(countries.count) * 39, 244))
            }
        }
        .padding(14)
        .frame(width: 315)
        .background(Color(white: 0.115))
        .onAppear { searchFocused = true }
    }

    private func row(_ code: String, name: String, detail: String? = nil) -> some View {
        let selected = code == model.voxCountry
        return Button { choose(code) } label: {
            HStack(spacing: 9) {
                VStack { routeIcon(code, automatic: code == VPNModel.automaticCountry) }
                    .frame(width: 28)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(name).font(.system(size: 13, weight: .semibold))
                    if let detail {
                        Text(detail).font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if selected {
                    Image(systemName: "checkmark").font(.system(size: 11, weight: .bold))
                        .accessibilityHidden(true)
                }
            }
            .padding(.horizontal, 7)
            .frame(minHeight: detail == nil ? 36 : 42)
            .background(.white.opacity(selected ? 0.12 : 0.035), in: RoundedRectangle(cornerRadius: 7))
            .contentShape(Rectangle())
        }
        .buttonStyle(VezdePress())
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

@ViewBuilder
private func routeIcon(_ code: String?, automatic: Bool) -> some View {
    if automatic {
        Image(systemName: "location.north.circle")
            .font(.system(size: 21, weight: .medium))
    } else if let code, code.utf8.count == 2, code.utf8.allSatisfy({ (65...90).contains($0) }) {
        Text(String(String.UnicodeScalarView(code.utf8.compactMap { UnicodeScalar(127397 + Int($0)) })))
            .font(.system(size: 20))
    } else {
        Image(systemName: "globe")
            .font(.system(size: 18, weight: .medium))
    }
}

struct VezdePress: ButtonStyle {
    var dimWhenDisabled = true

    func makeBody(configuration: Configuration) -> some View {
        VezdePressBody(configuration: configuration, dimWhenDisabled: dimWhenDisabled)
    }
}

private struct VezdePressBody: View {
    let configuration: ButtonStyle.Configuration
    let dimWhenDisabled: Bool
    @Environment(\.isEnabled) private var enabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var hovered = false

    var body: some View {
        configuration.label
            .opacity(enabled || !dimWhenDisabled ? 1 : 0.43)
            .brightness(hovered && enabled ? 0.07 : 0)
            .scaleEffect(configuration.isPressed && !reduceMotion ? 0.98 : 1)
            .animation(reduceMotion ? nil : .easeOut(duration: 0.14), value: configuration.isPressed)
            .onHover { hovered = $0 }
    }
}

private struct VezdeOrbitArt: View {
    private let deep = Color(red: 0.026, green: 0.124, blue: 0.12)
    private let earth = Color(red: 0.06, green: 0.42, blue: 0.35)
    private let light = Color(red: 0.63, green: 1, blue: 0.73)
    private let sun = Color(red: 1, green: 0.72, blue: 0.42)

    var body: some View {
        Canvas { context, size in
            let center = CGPoint(x: size.width * 0.65, y: size.height * 0.40)
            let radius = size.height * 0.32
            let globe = Path(ellipseIn: CGRect(x: center.x - radius, y: center.y - radius,
                                               width: radius * 2, height: radius * 2))
            context.fill(Path(CGRect(origin: .zero, size: size)),
                         with: .radialGradient(Gradient(colors: [earth.opacity(0.55), deep]),
                                               center: center, startRadius: 4, endRadius: size.width * 0.66))
            for x in stride(from: 15.0, to: size.width, by: 15) {
                for y in stride(from: 14.0, to: size.height, by: 15) {
                    let dot = CGRect(x: x, y: y, width: 1.25, height: 1.25)
                    context.fill(Path(ellipseIn: dot), with: .color(light.opacity(0.23)))
                }
            }

            let track = route(in: size, height: 0)
            let echo = route(in: size, height: 19)
            context.stroke(echo, with: .color(light.opacity(0.25)), style: StrokeStyle(lineWidth: 1, dash: [2, 5]))
            context.stroke(track, with: .color(light.opacity(0.55)), lineWidth: 1.3)
            context.fill(globe, with: .radialGradient(Gradient(colors: [light, earth, deep]),
                                                       center: CGPoint(x: center.x - radius * 0.43, y: center.y - radius * 0.57),
                                                       startRadius: 3, endRadius: radius * 1.63))
            context.drawLayer { layer in
                layer.clip(to: globe)
                for index in 0..<11 {
                    let x = center.x - radius * 1.65 + CGFloat(index) * 22
                    let stripe = Path { path in
                        path.move(to: CGPoint(x: x, y: center.y - radius * 1.13))
                        path.addQuadCurve(to: CGPoint(x: x + 96, y: center.y + radius * 1.15),
                                          control: CGPoint(x: x - 13, y: center.y + radius * 0.40))
                    }
                    layer.stroke(stripe, with: .color(light.opacity(index.isMultiple(of: 3) ? 0.58 : 0.33)),
                                 lineWidth: index.isMultiple(of: 3) ? 1.2 : 0.8)
                }
            }
            context.stroke(globe, with: .color(light.opacity(0.62)), lineWidth: 0.8)
            let front = Path { path in
                path.move(to: CGPoint(x: size.width * 0.30, y: size.height * 0.61))
                path.addQuadCurve(to: CGPoint(x: size.width * 0.95, y: size.height * 0.24),
                                  control: CGPoint(x: size.width * 0.78, y: size.height * 0.72))
            }
            context.stroke(front,
                           with: .linearGradient(Gradient(colors: [light.opacity(0.12), light, sun]),
                                                 startPoint: .zero, endPoint: CGPoint(x: size.width, y: 0)),
                           style: StrokeStyle(lineWidth: 1.8, lineCap: .round))
            for (x, y, r, color) in [(0.19, 0.30, 3.5, light), (0.36, 0.19, 2.1, light),
                                      (0.89, 0.28, 7.0, sun), (0.90, 0.59, 2.3, light),
                                      (0.27, 0.49, 2.0, sun), (0.81, 0.13, 1.9, light)] {
                let px = size.width * x
                let py = size.height * y
                context.fill(Path(ellipseIn: CGRect(x: px - r, y: py - r, width: 2 * r, height: 2 * r)),
                             with: .color(color))
            }
        }
    }

    private func route(in size: CGSize, height: CGFloat) -> Path {
        Path { path in
            path.move(to: CGPoint(x: -14, y: size.height * 0.49 + height))
            path.addCurve(to: CGPoint(x: size.width + 13, y: size.height * 0.29 + height),
                          control1: CGPoint(x: size.width * 0.26, y: size.height * 0.88 + height),
                          control2: CGPoint(x: size.width * 0.75, y: -size.height * 0.06 + height))
        }
    }
}
