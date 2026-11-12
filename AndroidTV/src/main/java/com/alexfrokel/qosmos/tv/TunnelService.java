package com.alexfrokel.qosmos.tv;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;

import java.io.File;
import java.io.IOException;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import go.Seq;
import io.nekohasekai.libbox.BridgeOptions;
import io.nekohasekai.libbox.BridgeSession;
import io.nekohasekai.libbox.CommandServer;
import io.nekohasekai.libbox.CommandServerHandler;
import io.nekohasekai.libbox.ConnectionOwner;
import io.nekohasekai.libbox.InterfaceUpdateListener;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.LocalDNSTransport;
import io.nekohasekai.libbox.NeighborUpdateListener;
import io.nekohasekai.libbox.NetworkInterfaceIterator;
import io.nekohasekai.libbox.OverrideOptions;
import io.nekohasekai.libbox.PlatformInterface;
import io.nekohasekai.libbox.PlatformUser;
import io.nekohasekai.libbox.RoutePrefix;
import io.nekohasekai.libbox.RoutePrefixIterator;
import io.nekohasekai.libbox.SetupOptions;
import io.nekohasekai.libbox.ShellSession;
import io.nekohasekai.libbox.StringIterator;
import io.nekohasekai.libbox.SystemProxyStatus;
import io.nekohasekai.libbox.TunOptions;
import io.nekohasekai.libbox.WIFIState;

public final class TunnelService extends VpnService implements PlatformInterface, CommandServerHandler {
    static final String START = "com.alexfrokel.qosmos.tv.START";
    static final String STOP = "com.alexfrokel.qosmos.tv.STOP";
    private static final String CHANNEL = "vpn";
    private static final int NOTIFICATION_ID = 1;
    enum State { IDLE, STARTING, CONNECTED, STOPPING }

    private static volatile State state = State.IDLE;
    private static volatile String error = "";
    private static boolean initialized;
    private static final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private volatile boolean stopRequested;
    private CommandServer engine;
    private ParcelFileDescriptor descriptor;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback networkCallback;

    static State state() { return state; }
    static String error() { return error; }

    @Override public void onCreate() {
        super.onCreate();
        connectivity = getSystemService(ConnectivityManager.class);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (STOP.equals(action)) {
            requestStop();
        } else if (START.equals(action) && state == State.IDLE) {
            error = "";
            state = State.STARTING;
            stopRequested = false;
            try {
                if (Build.VERSION.SDK_INT >= 34) {
                    startForeground(NOTIFICATION_ID, notification("Подключение"),
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
                } else {
                    startForeground(NOTIFICATION_ID, notification("Подключение"));
                }
                worker.execute(this::connect);
            } catch (RuntimeException e) {
                fail("Android не разрешил запустить VPN. Открой приложение и выдай разрешение.");
            }
        } else if (state == State.IDLE) {
            stopSelf(startId);
        }
        return START_NOT_STICKY;
    }

    private void connect() {
        try {
            if (stopRequested) return;
            RealityProfile profile = new ProfileStore(this).selected();
            if (profile == null || prepare(this) != null) throw new IOException();
            if (!initialized) {
                Seq.setContext(getApplicationContext());
                File directory = new File(getNoBackupFilesDir(), "engine");
                if (!directory.isDirectory() && !directory.mkdirs()) throw new IOException();
                SetupOptions options = new SetupOptions();
                options.setBasePath(directory.getAbsolutePath());
                options.setWorkingPath(directory.getAbsolutePath());
                options.setTempPath(getCacheDir().getAbsolutePath());
                Libbox.setup(options);
                initialized = true;
            }
            engine = Libbox.newCommandServer(this, this);
            // This app controls the engine directly, without starting its local RPC listener.
            engine.startOrReloadService(profile.config(), new OverrideOptions());
            main.post(() -> {
                if (!stopRequested && state == State.STARTING) {
                    state = State.CONNECTED;
                    getSystemService(NotificationManager.class).notify(NOTIFICATION_ID, notification("VPN включён"));
                }
            });
        } catch (Exception | LinkageError e) {
            cleanup();
            main.post(() -> {
                if (!stopRequested) fail("Не удалось запустить VPN. Проверь профиль и подключение к сети.");
            });
        }
    }

    private void requestStop() {
        if (state == State.STOPPING) return;
        state = State.STOPPING;
        stopRequested = true;
        worker.execute(() -> {
            cleanup();
            main.post(this::finish);
        });
    }

    @Override public void onRevoke() {
        main.post(this::requestStop);
    }

    @Override public void onDestroy() {
        if (!stopRequested && state != State.IDLE) {
            stopRequested = true;
            state = State.STOPPING;
            worker.execute(() -> {
                cleanup();
                main.post(() -> state = State.IDLE);
            });
        }
        super.onDestroy();
    }

    private void fail(String message) {
        error = message;
        finish();
    }

    private void finish() {
        stopForeground(STOP_FOREGROUND_REMOVE);
        state = State.IDLE;
        stopSelf();
    }

    private void cleanup() {
        if (engine != null) {
            try { engine.closeService(); } catch (Exception ignored) { }
            engine.close();
            engine = null;
        }
        closeDefaultInterfaceMonitor(null);
        if (descriptor != null) {
            try { descriptor.close(); } catch (IOException ignored) { }
            descriptor = null;
        }
    }

    private Notification notification(String text) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL, "Qosmos VPN", NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop = PendingIntent.getService(this, 1, new Intent(this, TunnelService.class).setAction(STOP),
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL).setContentTitle("Qosmos VPN").setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock).setContentIntent(open).setOngoing(true)
            .addAction(new Notification.Action.Builder(null, "Отключить", stop).build()).build();
    }

    @Override public int openTun(TunOptions options) throws Exception {
        if (prepare(this) != null) throw new IOException("VPN permission revoked");
        Builder builder = new Builder().setSession("Qosmos VPN").setMtu(options.getMTU());
        addAddresses(builder, options.getInet4Address());
        addAddresses(builder, options.getInet6Address());
        builder.addRoute("0.0.0.0", 0);
        builder.addRoute("::", 0);
        StringIterator dns = options.getDNSServerAddress();
        while (dns.hasNext()) builder.addDnsServer(dns.next());
        Network network = underlying();
        if (network != null) builder.setUnderlyingNetworks(new Network[]{network});
        descriptor = builder.establish();
        if (descriptor == null) throw new IOException("Unable to establish VPN");
        return descriptor.getFd();
    }

    private static void addAddresses(Builder builder, RoutePrefixIterator addresses) {
        while (addresses.hasNext()) {
            RoutePrefix address = addresses.next();
            builder.addAddress(address.address(), address.prefix());
        }
    }

    @Override public boolean usePlatformAutoDetectInterfaceControl() { return true; }
    @Override public void autoDetectInterfaceControl(int fd) throws Exception {
        if (!protect(fd)) throw new IOException("Unable to protect outbound socket");
    }

    private Network underlying() {
        Network active = connectivity.getActiveNetwork();
        if (physical(active)) return active;
        Network candidate = null;
        for (Network network : connectivity.getAllNetworks()) {
            if (!physical(network)) continue;
            NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
            if (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) return network;
            if (candidate == null) candidate = network;
        }
        return candidate;
    }

    private boolean physical(Network network) {
        if (network == null) return false;
        NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
        return caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
    }

    @Override public synchronized void startDefaultInterfaceMonitor(InterfaceUpdateListener listener) {
        closeDefaultInterfaceMonitor(null);
        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network network) { updateInterface(listener, this); }
            @Override public void onLost(Network network) { updateInterface(listener, this); }
            @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
                updateInterface(listener, this);
            }
        };
        connectivity.registerNetworkCallback(new NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), networkCallback);
        updateInterface(listener, networkCallback);
    }

    private synchronized void updateInterface(InterfaceUpdateListener listener, ConnectivityManager.NetworkCallback owner) {
        if (owner != networkCallback || stopRequested) return;
        Network network = underlying();
        LinkProperties props = network == null ? null : connectivity.getLinkProperties(network);
        String name = props == null ? null : props.getInterfaceName();
        NetworkCapabilities caps = network == null ? null : connectivity.getNetworkCapabilities(network);
        try {
            NetworkInterface iface = name == null ? null : NetworkInterface.getByName(name);
            listener.updateDefaultInterface(iface == null ? "" : name, iface == null ? -1 : iface.getIndex(),
                caps != null && !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED), false);
            setUnderlyingNetworks(network == null ? null : new Network[]{network});
        } catch (IOException ignored) { }
    }

    @Override public synchronized void closeDefaultInterfaceMonitor(InterfaceUpdateListener listener) {
        ConnectivityManager.NetworkCallback previous = networkCallback;
        networkCallback = null;
        if (previous != null) {
            try { connectivity.unregisterNetworkCallback(previous); } catch (IllegalArgumentException ignored) { }
        }
    }

    @Override public NetworkInterfaceIterator getInterfaces() throws Exception {
        List<io.nekohasekai.libbox.NetworkInterface> interfaces = new ArrayList<>();
        for (Network network : connectivity.getAllNetworks()) {
            if (!physical(network)) continue;
            LinkProperties props = connectivity.getLinkProperties(network);
            if (props == null || props.getInterfaceName() == null) continue;
            NetworkInterface iface = NetworkInterface.getByName(props.getInterfaceName());
            if (iface == null) continue;
            io.nekohasekai.libbox.NetworkInterface item = new io.nekohasekai.libbox.NetworkInterface();
            item.setName(iface.getName());
            item.setIndex(iface.getIndex());
            item.setMTU(iface.getMTU());
            interfaces.add(item);
        }
        Iterator<io.nekohasekai.libbox.NetworkInterface> iterator = interfaces.iterator();
        return new NetworkInterfaceIterator() {
            @Override public boolean hasNext() { return iterator.hasNext(); }
            @Override public io.nekohasekai.libbox.NetworkInterface next() { return iterator.next(); }
        };
    }

    @Override public LocalDNSTransport localDNSTransport() { return null; }
    @Override public boolean underNetworkExtension() { return false; }
    @Override public boolean includeAllNetworks() { return false; }
    @Override public WIFIState readWIFIState() { return null; }
    @Override public void clearDNSCache() { }
    @Override public void sendNotification(io.nekohasekai.libbox.Notification notification) { }
    @Override public void cancelNotification(String identifier, int typeId) { }
    @Override public void startNeighborMonitor(NeighborUpdateListener listener) throws Exception { throw unsupported(); }
    @Override public void closeNeighborMonitor(NeighborUpdateListener listener) { }
    @Override public void registerMyInterface(String name) { }
    @Override public boolean usePlatformShell() { return false; }
    @Override public void checkPlatformShell() throws Exception { throw unsupported(); }
    @Override public ShellSession openShellSession(PlatformUser user, String command, StringIterator env,
            String term, int rows, int cols) throws Exception { throw unsupported(); }
    @Override public PlatformUser lookupUser(String username) throws Exception { throw unsupported(); }
    @Override public String lookupSFTPServer() throws Exception { throw unsupported(); }
    @Override public String readSystemSSHHostKey() throws Exception { throw unsupported(); }
    @Override public String tailscaleHostname() { return ""; }
    @Override public boolean usePlatformBridge() { return false; }
    @Override public BridgeSession createBridge(BridgeOptions options) throws Exception { throw unsupported(); }
    @Override public ConnectionOwner findConnectionOwner(int protocol, String sourceAddress, int sourcePort,
            String destinationAddress, int destinationPort) throws Exception { throw unsupported(); }
    @Override public void serviceStop() { main.post(this::requestStop); }
    @Override public void serviceReload() throws Exception { throw unsupported(); }
    @Override public SystemProxyStatus getSystemProxyStatus() { return new SystemProxyStatus(); }
    @Override public void setSystemProxyEnabled(boolean enabled) throws Exception { throw unsupported(); }
    @Override public void triggerNativeCrash() throws Exception { throw unsupported(); }
    @Override public void writeDebugMessage(String message) { }
    @Override public int connectSSHAgent() throws Exception { throw unsupported(); }

    private static IOException unsupported() { return new IOException("Unsupported operation"); }
}
