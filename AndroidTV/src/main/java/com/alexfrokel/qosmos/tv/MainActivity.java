package com.alexfrokel.qosmos.tv;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final int VPN_PERMISSION = 100;
    private static final int BACKGROUND = 0xff0e0f12;
    private static final int CARD = 0xff1c1d22;
    private static final int TEXT = 0xfff3f0ed;
    private static final int SECONDARY = 0xffb3b5c1;
    private static final int ACCENT = 0xffffa96b;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final List<Button> profileControls = new ArrayList<>();
    private ProfileStore store;
    private TextView status;
    private TextView message;
    private Button toggle;
    private Button profilesFocus;
    private boolean loading;
    private String notice = "";
    private boolean sourcePage;
    private boolean settingsChild;
    private int catalogRequest;

    private final Runnable observeVpn = new Runnable() {
        @Override public void run() {
            refreshStatus();
            handler.postDelayed(this, 400);
        }
    };

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        store = new ProfileStore(this);
        showHome(false);
    }

    @Override protected void onResume() {
        super.onResume();
        handler.post(observeVpn);
    }

    @Override protected void onPause() {
        handler.removeCallbacks(observeVpn);
        super.onPause();
    }

    @Override protected void onDestroy() {
        handler.removeCallbacksAndMessages(null);
        worker.shutdownNow();
        super.onDestroy();
    }

    private void showHome(boolean focusVpn) {
        catalogRequest++;
        sourcePage = false;
        profileControls.clear();
        profilesFocus = null;
        LinearLayout root = column();
        root.setBackgroundColor(BACKGROUND);
        root.setPadding(dp(36), dp(22), dp(36), dp(20));
        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        ImageView logo = new ImageView(this);
        logo.setImageResource(R.drawable.qosmos_icon);
        header.addView(logo, new LinearLayout.LayoutParams(dp(44), dp(44)));
        TextView brand = label("Qosmos VPN", 28, TEXT, true);
        LinearLayout.LayoutParams brandParams = new LinearLayout.LayoutParams(-2, -2);
        brandParams.leftMargin = dp(8);
        header.addView(brand, brandParams);
        root.addView(header);

        LinearLayout content = new LinearLayout(this);
        LinearLayout.LayoutParams contentParams = new LinearLayout.LayoutParams(-1, 0, 1);
        contentParams.topMargin = dp(14);
        root.addView(content, contentParams);

        ScrollView profilesScroll = new ScrollView(this);
        profilesScroll.setFillViewport(true);
        content.addView(profilesScroll, new LinearLayout.LayoutParams(0, -1, 1.18f));
        LinearLayout list = column();
        list.setPadding(dp(8), dp(8), dp(10), dp(8));
        profilesScroll.addView(list);
        list.addView(label("Профили", 21, SECONDARY, true));
        List<RealityProfile> profiles = store.profiles();
        RealityProfile selected = store.selected();
        if (profiles.isEmpty()) {
            TextView empty = label("Открой «Настройки → Загрузить конфиг».", 17, SECONDARY, false);
            empty.setPadding(0, dp(12), dp(12), 0);
            list.addView(empty);
        }
        for (int index = 0; index < profiles.size(); index++) {
            RealityProfile profile = profiles.get(index);
            int selectedIndex = index;
            boolean current = selected != null && selected.sameEndpointAndCredentials(profile);
            Button item = button((current ? "✓  " : "") + profile.name + "\n" + profile.endpoint(), () -> {
                store.select(selectedIndex);
                notice = "";
                showHome(true);
            });
            item.setMaxLines(2);
            item.setEllipsize(TextUtils.TruncateAt.END);
            addButton(list, item, 66);
            if (current) profilesFocus = item;
            profileControls.add(item);
        }

        ScrollView actionsScroll = new ScrollView(this);
        LinearLayout.LayoutParams actionsParams = new LinearLayout.LayoutParams(0, -1, 1f);
        actionsParams.leftMargin = dp(20);
        content.addView(actionsScroll, actionsParams);
        LinearLayout actions = column();
        actions.setPadding(dp(8), dp(8), dp(8), dp(8));
        actionsScroll.addView(actions);
        status = label("", 24, TEXT, true);
        actions.addView(status);
        toggle = button("Подключить", this::toggleVpn);
        addButton(actions, toggle, 50);
        Button settings = button("Настройки", this::showSettings);
        addButton(actions, settings, 50);
        profileControls.add(settings);
        message = label("", 15, SECONDARY, false);
        message.setPadding(0, dp(10), 0, 0);
        actions.addView(message, new LinearLayout.LayoutParams(-1, -2));

        setContentView(root);
        refreshStatus();
        if (focusVpn && toggle.isEnabled()) toggle.requestFocus();
        else if (profilesFocus != null && profilesFocus.isEnabled()) profilesFocus.requestFocus();
        else if (toggle.isEnabled()) toggle.requestFocus();
        else settings.requestFocus();
    }

    private LinearLayout settingsPage(String title) {
        sourcePage = true;
        LinearLayout screen = column();
        screen.setBackgroundColor(BACKGROUND);
        screen.setPadding(dp(48), dp(24), dp(48), dp(16));
        screen.addView(label(title, 27, TEXT, true));
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(screen);
        setContentView(scroll);
        return screen;
    }

    private void showSettings() {
        catalogRequest++;
        settingsChild = false;
        LinearLayout screen = settingsPage("Настройки");
        Button catalog = button("Загрузить конфиг", this::showCatalog);
        addButton(screen, catalog, 54);
        addButton(screen, button("Ссылка подписки", this::showSource), 50);
        if (!store.source().isEmpty()) {
            addButton(screen, button("Обновить подписку", () -> fetch(store.source())), 50);
        }
        if (new File(getFilesDir(), ProfileStore.PENDING).isFile()) {
            addButton(screen, button("Импорт с Mac", this::importFromMac), 50);
        }
        addButton(screen, button("Назад", () -> showHome(false)), 50);
        catalog.requestFocus();
    }

    private void showCatalog() {
        int request = ++catalogRequest;
        settingsChild = true;
        LinearLayout screen = settingsPage("Загрузить конфиг");
        TextView feedback = label("Загружаем каталог…", 18, SECONDARY, false);
        feedback.setPadding(0, dp(10), 0, dp(6));
        screen.addView(feedback);
        LinearLayout choices = column();
        screen.addView(choices);
        Button retry = button("Обновить каталог", this::showCatalog);
        addButton(screen, retry, 50);
        retry.setVisibility(View.GONE);
        Button back = button("Назад", this::showSettings);
        addButton(screen, back, 50);
        back.requestFocus();

        worker.execute(() -> {
            List<RealityProfile> available = null;
            String detail = "";
            try {
                available = TvCatalog.download(getApplicationContext());
                if (available.isEmpty()) detail = "В каталоге пока нет профилей.";
            } catch (TvCatalog.CatalogNotConfigured e) {
                detail = "Для каталога установи персональный APK Qosmos TV.";
            } catch (IOException e) {
                detail = "Каталог недоступен. Проверь подключение и попробуй ещё раз.";
            } catch (Exception e) {
                detail = "Не удалось открыть каталог профилей.";
            }
            List<RealityProfile> profiles = available;
            String result = detail;
            runOnUiThread(() -> {
                if (isDestroyed() || request != catalogRequest) return;
                retry.setVisibility(View.VISIBLE);
                if (profiles == null || profiles.isEmpty()) {
                    feedback.setText(result);
                    retry.requestFocus();
                    return;
                }
                feedback.setText("Выбери профиль пультом.");
                for (RealityProfile profile : profiles) {
                    Button item = button(profile.name, () -> selectCatalogProfile(profile));
                    item.setSingleLine(true);
                    item.setEllipsize(TextUtils.TruncateAt.END);
                    addButton(choices, item, 54);
                }
                choices.getChildAt(0).requestFocus();
            });
        });
    }

    private void selectCatalogProfile(RealityProfile profile) {
        if (TunnelService.state() != TunnelService.State.IDLE) return;
        try {
            store.importLocal(java.util.Collections.singletonList(profile));
            List<RealityProfile> profiles = store.profiles();
            for (int index = 0; index < profiles.size(); index++) {
                if (profile.sameEndpointAndCredentials(profiles.get(index))) {
                    store.select(index);
                    break;
                }
            }
            notice = "Профиль «" + profile.name + "» готов к подключению.";
        } catch (IOException e) {
            notice = "Не удалось сохранить профиль.";
        }
        showHome(true);
    }

    private void showSource() {
        sourcePage = true;
        settingsChild = true;
        LinearLayout screen = column();
        screen.setBackgroundColor(BACKGROUND);
        screen.setPadding(dp(48), dp(24), dp(48), dp(16));
        screen.addView(label("Ссылка подписки", 27, TEXT, true));
        TextView help = label("Введи HTTPS-адрес списка профилей VLESS + REALITY. Его можно вставить с телефона, используя телефон как пульт с клавиатурой.", 17, SECONDARY, false);
        help.setPadding(0, dp(8), 0, dp(8));
        screen.addView(help);
        EditText field = new EditText(this);
        field.setSingleLine(true);
        field.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        field.setContentDescription("HTTPS-адрес подписки");
        field.setHint("https://");
        field.setText(store.source());
        screen.addView(field, new LinearLayout.LayoutParams(-1, dp(52)));
        addButton(screen, button("Загрузить профили", () -> {
            String link = field.getText().toString().trim();
            if (!link.regionMatches(true, 0, "https://", 0, 8)) {
                field.setError("Введи HTTPS-ссылку");
                return;
            }
            fetch(link);
        }), 50);
        addButton(screen, button("Назад", this::showSettings), 50);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(screen);
        setContentView(scroll);
        field.requestFocus();
    }

    private void fetch(String source) {
        if (loading || TunnelService.state() != TunnelService.State.IDLE) return;
        loading = true;
        notice = "Загружаем профили…";
        showHome(false);
        worker.execute(() -> {
            List<RealityProfile> profiles = null;
            String error = "";
            try {
                profiles = ProfileStore.download(source);
            } catch (IllegalArgumentException e) {
                error = "Источник должен содержать прямые ссылки VLESS + REALITY по TCP.";
            } catch (IOException e) {
                error = "Не удалось загрузить список. Проверь HTTPS-ссылку и подключение.";
            }
            List<RealityProfile> result = profiles;
            String failure = error;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                loading = false;
                notice = failure;
                if (result != null) {
                    try {
                        store.replaceRemote(source, result);
                        notice = "Загружено профилей: " + result.size();
                    } catch (IOException e) {
                        notice = "Не удалось сохранить профили.";
                    }
                }
                showHome(result != null);
            });
        });
    }

    private void importFromMac() {
        File pending = new File(getFilesDir(), ProfileStore.PENDING);
        if (!pending.isFile()) {
            notice = "Сначала отправь файл профиля с Mac.";
            refreshStatus();
            return;
        }
        List<RealityProfile> imported;
        try (FileInputStream input = new FileInputStream(pending)) {
            imported = RealityProfile.parseList(ProfileStore.read(input));
        } catch (IOException | IllegalArgumentException e) {
            notice = "В файле нужны прямые ссылки VLESS + REALITY по TCP.";
            refreshStatus();
            return;
        }
        new AlertDialog.Builder(this)
            .setTitle("Импорт с Mac")
            .setMessage("Добавить полученные профили? Всего: " + imported.size())
            .setNegativeButton("Отмена", null)
            .setPositiveButton("Добавить", (dialog, which) -> {
                try {
                    store.importLocal(imported);
                    pending.delete();
                    notice = "Импортировано профилей: " + imported.size();
                } catch (IOException e) {
                    notice = "Не удалось сохранить профили.";
                }
                showHome(true);
            }).show();
    }

    private void toggleVpn() {
        TunnelService.State state = TunnelService.state();
        if (state == TunnelService.State.CONNECTED || state == TunnelService.State.STARTING) {
            startService(new Intent(this, TunnelService.class).setAction(TunnelService.STOP));
        } else if (state == TunnelService.State.IDLE && store.selected() != null) {
            notice = "";
            Intent permission = VpnService.prepare(this);
            if (permission != null) startActivityForResult(permission, VPN_PERMISSION);
            else startVpn();
        }
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != VPN_PERMISSION) return;
        if (result == RESULT_OK) startVpn();
        else notice = "Разрешение Android на создание VPN не выдано.";
        refreshStatus();
    }

    private void startVpn() {
        startForegroundService(new Intent(this, TunnelService.class).setAction(TunnelService.START));
    }

    private void refreshStatus() {
        if (sourcePage || status == null) return;
        TunnelService.State state = TunnelService.state();
        boolean idle = state == TunnelService.State.IDLE && !loading;
        switch (state) {
            case STARTING: status.setText("Подключение…"); break;
            case CONNECTED: status.setText("VPN включён"); break;
            case STOPPING: status.setText("Отключение…"); break;
            default: status.setText("VPN выключен");
        }
        toggle.setText(state == TunnelService.State.IDLE ? "Подключить" : "Отключить");
        toggle.setEnabled(!loading && state != TunnelService.State.STOPPING
            && (state != TunnelService.State.IDLE || store.selected() != null));
        for (Button button : profileControls) button.setEnabled(idle);
        String error = TunnelService.error();
        message.setText(notice.isEmpty() ? error : notice);
    }

    @Override public void onBackPressed() {
        if (sourcePage && settingsChild) showSettings();
        else if (sourcePage) showHome(false);
        else super.onBackPressed();
    }

    private LinearLayout column() {
        LinearLayout result = new LinearLayout(this);
        result.setOrientation(LinearLayout.VERTICAL);
        return result;
    }

    private TextView label(String text, int size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(color);
        view.setTextSize(size);
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }

    private Button button(String text, Runnable onClick) {
        Button view = new Button(this);
        view.setText(text);
        view.setAllCaps(false);
        view.setTextSize(17);
        view.setTextColor(TEXT);
        view.setGravity(Gravity.CENTER_VERTICAL | Gravity.START);
        view.setPadding(dp(14), dp(4), dp(14), dp(4));
        view.setFocusable(true);
        view.setBackground(shape(false));
        view.setOnClickListener(v -> onClick.run());
        view.setOnFocusChangeListener((v, focused) -> {
            view.setBackground(shape(focused));
            view.setTextColor(focused ? Color.BLACK : TEXT);
        });
        return view;
    }

    private GradientDrawable shape(boolean focused) {
        GradientDrawable shape = new GradientDrawable();
        shape.setCornerRadius(dp(10));
        shape.setColor(focused ? ACCENT : CARD);
        return shape;
    }

    private void addButton(LinearLayout parent, Button view, int height) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(height));
        params.topMargin = dp(8);
        parent.addView(view, params);
    }

    private int dp(int size) {
        return Math.round(size * getResources().getDisplayMetrics().density);
    }
}
