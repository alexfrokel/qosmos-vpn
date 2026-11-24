import SwiftUI

enum VezdeLayout {
    static let width: CGFloat = 466
    static let contentHeight: CGFloat = 570
    static let ink = Color(red: 0.95, green: 0.97, blue: 0.96)
    static let muted = Color(red: 0.66, green: 0.71, blue: 0.70)
    static let mint = Color(red: 0.52, green: 0.98, blue: 0.73)

    static func background(connected: Bool) -> Color {
        connected ? Color(red: 0.047, green: 0.073, blue: 0.068) : Color(white: 0.072)
    }

    static func panel(connected: Bool) -> Color {
        connected ? Color(red: 0.069, green: 0.118, blue: 0.106) : Color(white: 0.103)
    }
}

enum VezdeTab: String, CaseIterable {
    case home = "Главная"
    case profile = "Профиль"
    case settings = "Настройки"

    var symbol: String {
        switch self {
        case .home: return "house"
        case .profile: return "person.crop.circle"
        case .settings: return "gearshape"
        }
    }
}

struct VezdeNavigationBar: View {
    @ObservedObject var preferences: AppPreferences
    let current: VezdeTab
    let connected: Bool
    var navigate: (VezdeTab) -> Void

    var body: some View {
        HStack(spacing: 8) {
            ForEach(VezdeTab.allCases, id: \.self) { tab in
                let selected = tab == current
                Button { navigate(tab) } label: {
                    VStack(spacing: 5) {
                        Image(systemName: tab.symbol)
                            .font(.system(size: 18, weight: selected ? .semibold : .medium))
                        Text(preferences.text(tab.rawValue))
                            .font(.system(size: 11, weight: selected ? .semibold : .medium))
                    }
                    .frame(maxWidth: .infinity, minHeight: 48)
                    .foregroundStyle(selected ? (connected ? VezdeLayout.mint : VezdeLayout.ink) : VezdeLayout.muted)
                    .background(.white.opacity(selected ? 0.08 : 0), in: RoundedRectangle(cornerRadius: 9))
                    .contentShape(Rectangle())
                }
                .buttonStyle(VezdePress())
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
        }
        .padding(7)
        .background(VezdeLayout.panel(connected: connected), in: RoundedRectangle(cornerRadius: 15))
        .overlay(RoundedRectangle(cornerRadius: 15).strokeBorder(.white.opacity(0.08)))
        .padding(.horizontal, 20)
        .padding(.bottom, 14)
    }
}

struct VezdeAccountView: View {
    @ObservedObject var model: VPNModel
    @ObservedObject var preferences: AppPreferences
    @State private var activationCode = ""

    private var connected: Bool { model.state == .connected }
    private var panel: Color { VezdeLayout.panel(connected: connected) }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text(preferences.text("Профиль"))
                    .font(.system(size: 29, weight: .bold, design: .rounded))
                    .tracking(-0.9)
                Spacer()
                if model.voxActivated {
                    Button { model.refreshVoxUsage() } label: {
                        Image(systemName: "arrow.clockwise")
                            .font(.system(size: 15, weight: .medium))
                            .frame(width: 36, height: 36)
                            .background(panel, in: RoundedRectangle(cornerRadius: 9))
                    }
                    .buttonStyle(VezdePress())
                    .accessibilityLabel(preferences.text("Обновить данные подписки"))
                    .help(preferences.text("Обновить данные подписки"))
                }
            }
            if model.voxActivated {
                identity
                subscription
                if let usage = model.voxUsage { usageSummary(usage) }
                if model.voxUsageUnavailable {
                    Text(preferences.text("Данные подписки недоступны. Обновить."))
                        .font(.system(size: 12))
                        .foregroundStyle(VezdeLayout.muted)
                }
                Button(preferences.text("Выйти из подписки"), action: model.clearVoxAccess)
                    .buttonStyle(.link)
                    .disabled(!model.isIdle || model.voxBusy)
            } else {
                activation
            }
            Spacer(minLength: 0)
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .foregroundStyle(VezdeLayout.ink)
        .onAppear { if model.voxActivated { model.refreshVoxUsage() } }
        .onDisappear { activationCode = "" }
    }

    private var identity: some View {
        HStack(spacing: 13) {
            Image(systemName: "envelope")
                .font(.system(size: 19, weight: .medium))
                .frame(width: 45, height: 45)
                .foregroundStyle(connected ? VezdeLayout.mint : VezdeLayout.ink)
                .background(.white.opacity(0.075), in: RoundedRectangle(cornerRadius: 11))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(preferences.text("Логин (почта)"))
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(VezdeLayout.muted)
                Text(model.voxUsage?.email ?? preferences.text("Почта не указана"))
                    .font(.system(size: 17, weight: .semibold))
                    .textSelection(.enabled)
                    .lineLimit(2)
            }
            Spacer()
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(panel, in: RoundedRectangle(cornerRadius: 15))
    }

    private var subscription: some View {
        VStack(alignment: .leading, spacing: 13) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(preferences.text("Демо-подписка"))
                    .font(.system(size: 21, weight: .semibold, design: .rounded))
                Spacer(minLength: 4)
                if let status = subscriptionStatus {
                    Text(preferences.text(status))
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(model.voxUsage?.subscriptionStatus == "active" ? VezdeLayout.mint : VezdeLayout.muted)
                        .padding(.horizontal, 9)
                        .padding(.vertical, 5)
                        .background(.white.opacity(0.07), in: Capsule())
                }
            }
            Divider().overlay(.white.opacity(0.06))
            HStack(spacing: 8) {
                Label(preferences.text("Действует до"), systemImage: "calendar")
                    .foregroundStyle(VezdeLayout.muted)
                Spacer(minLength: 5)
                Text(expirationLabel)
                    .fontWeight(.semibold)
                    .monospacedDigit()
            }
            .font(.system(size: 13))
            VStack(alignment: .leading, spacing: 5) {
                Button {} label: {
                    Label(preferences.text("Продлить подписку"), systemImage: "arrow.clockwise")
                        .font(.system(size: 14, weight: .semibold))
                        .frame(maxWidth: .infinity, minHeight: 43)
                        .background(.white.opacity(0.10), in: RoundedRectangle(cornerRadius: 9))
                }
                .buttonStyle(VezdePress())
                .disabled(true)
                Text(preferences.text("Оплата пока недоступна"))
                    .font(.system(size: 11))
                    .foregroundStyle(VezdeLayout.muted)
            }
        }
        .padding(15)
        .background(panel, in: RoundedRectangle(cornerRadius: 15))
    }

    private func usageSummary(_ usage: VoxUsage) -> some View {
        VStack(spacing: 9) {
            usageRow("Устройства", icon: "laptopcomputer.and.iphone",
                     value: "\(usage.devicesUsed) / \(usage.deviceLimit)")
            Divider()
            usageRow("Трафик за месяц", icon: "arrow.up.arrow.down",
                     value: ByteCountFormatter.string(fromByteCount: usage.monthlyBytes, countStyle: .decimal))
        }
        .padding(13)
        .background(panel, in: RoundedRectangle(cornerRadius: 13))
    }

    private func usageRow(_ title: String, icon: String, value: String) -> some View {
        HStack {
            Label(preferences.text(title), systemImage: icon)
                .foregroundStyle(VezdeLayout.muted)
            Spacer()
            Text(value)
                .fontWeight(.semibold)
                .monospacedDigit()
        }
        .font(.system(size: 13))
        .accessibilityElement(children: .combine)
    }

    private var activation: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(preferences.text("Введите код активации подписки."))
                .font(.system(size: 14))
                .foregroundStyle(VezdeLayout.muted)
            SecureField(preferences.text("Код активации"), text: $activationCode)
                .textFieldStyle(.roundedBorder)
                .disabled(model.voxBusy)
            HStack {
                if model.voxBusy { ProgressView().controlSize(.small) }
                Spacer()
                Button(preferences.text("Активировать")) {
                    model.activateVox(activationCode) { activationCode = "" }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(!model.voxAvailable || !model.isIdle || model.voxBusy
                          || activationCode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(15)
        .background(panel, in: RoundedRectangle(cornerRadius: 15))
    }

    private var subscriptionStatus: String? {
        switch model.voxUsage?.subscriptionStatus {
        case "active": return "Активна"
        case "suspended": return "Приостановлена"
        case "pending": return "Ожидает подключения"
        default: return nil
        }
    }

    private var expirationLabel: String {
        guard let timestamp = model.voxUsage?.expiresAt,
              let date = ISO8601DateFormatter().date(from: timestamp) else {
            return preferences.text("Дата не указана")
        }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: preferences.language.rawValue)
        formatter.dateStyle = .medium
        return formatter.string(from: date)
    }
}
