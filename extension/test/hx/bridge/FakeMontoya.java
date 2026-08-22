package hx.bridge;

/**
 * The few Montoya surfaces the bridge touches. MontoyaApi is an interface with
 * 21 sub-interfaces; faking all of it would be a project. The bridge needs
 * logging and a version string, so that is what this provides.
 */
public final class FakeMontoya {

    public static final class Logger {
        public final StringBuilder out = new StringBuilder();
        public final StringBuilder err = new StringBuilder();
        public void info(String s) { out.append(s).append('\n'); }
        public void error(String s) { err.append(s).append('\n'); }
        public boolean sawInfo(String needle) { return out.toString().contains(needle); }
        public boolean sawError(String needle) { return err.toString().contains(needle); }
    }
}
