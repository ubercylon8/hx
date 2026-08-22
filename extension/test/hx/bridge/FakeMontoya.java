package hx.bridge;

/**
 * The few Montoya surfaces the bridge touches. MontoyaApi is an interface with
 * 21 sub-interfaces; faking all of it would be a project. The bridge needs
 * logging and a version string, so that is what this provides.
 */
public final class FakeMontoya {

    /** StringBuffer, not StringBuilder: the bridge logs from its read-loop
     *  thread while the test reads from main. StringBuilder is not thread-safe,
     *  so that pairing can lose or corrupt a line -- in the one assertion that
     *  proves the deny-all transition was announced. */
    public static final class Logger implements BridgeClient.Log {
        public final StringBuffer out = new StringBuffer();
        public final StringBuffer err = new StringBuffer();
        public void info(String s) { out.append(s).append('\n'); }
        public void error(String s) { err.append(s).append('\n'); }
        public boolean sawInfo(String needle) { return out.toString().contains(needle); }
        public boolean sawError(String needle) { return err.toString().contains(needle); }
    }
}
