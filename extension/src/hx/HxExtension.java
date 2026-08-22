package hx;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import hx.bridge.BridgeClient;

import java.nio.file.Path;

/**
 * Burp entry point. Reads its socket path, engagement id and instance id from
 * system properties so the harness controls them at launch, then dials in on a
 * background thread and stays in DENY-ALL until configured.
 */
public class HxExtension implements BurpExtension {

    private BridgeClient client;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("hx bridge");

        String sock = System.getProperty("hx.socket");
        String engagement = System.getProperty("hx.engagement");
        String instance = System.getProperty("hx.instance", "unknown");

        if (sock == null || engagement == null) {
            api.logging().logToError(
                "hx: -Dhx.socket and -Dhx.engagement are required; extension idle");
            return;
        }
        System.setProperty("hx.burp.version", api.burpSuite().version().toString());

        client = new BridgeClient(Path.of(sock), engagement, instance, new BridgeClient.Log() {
            public void info(String s)  { api.logging().logToOutput(s); }
            public void error(String s) { api.logging().logToError(s); }
        });
        Thread t = new Thread(() -> {
            try {
                client.connect();
            } catch (Exception e) {
                api.logging().logToError("hx: bridge connect failed: " + e);
            }
        }, "hx-bridge");
        t.setDaemon(true);
        t.start();

        api.extension().registerUnloadingHandler(() -> {
            if (client != null) client.close();
        });
        api.logging().logToOutput("hx: bridge dialling " + sock);
    }
}
