// extension/test/hx/send/HostilePath.java
package hx.send;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.spi.FileSystemProvider;
import java.util.Map;
import java.util.Set;

/**
 * A Path on a filesystem that answers whatever the test tells it to, including
 * by throwing something java.nio never throws.
 *
 * WHY THIS EXISTS, when HaltSwitchTest otherwise uses real files and a real
 * zip filesystem. HaltSwitch's javadoc says every filesystem call here is
 * treated as able to throw something the file does not name, and that the
 * exception-from-outside-the-repo class of defect has opened three guards on
 * this project. Two of those catch clauses -- both inside
 * parentIsNotADirectory() -- had no input that could reach them:
 *
 *   * `parentIsNotADirectory()` is entered ONLY from pollOnce()'s
 *     NoSuchFileException clause, so the sentinel read has to have answered
 *     ENOENT first; and
 *   * on every real parent shape that then follows -- absent, dangling
 *     symlink, regular file, unreadable directory -- the parent read either
 *     succeeds or throws an IOException too.
 *
 * So on real filesystems the only way in is a TOCTOU race: the parent replaced
 * between the two stats. A race is not a test. MEASURED on this branch, before
 * this class existed: narrowing either clause -- the first to
 * `RuntimeException`, the second to `IOException` -- left the whole Java suite
 * at 9 x ALL PASS / 1396 ok / 0 FAIL, and so did making the first one return
 * null, which is the fail-OPEN direction.
 *
 * A wrapper around a real Path cannot do this job: every real provider casts
 * its argument to its own Path type and throws ProviderMismatchException on
 * anything else. The provider has to be ours all the way down.
 *
 * Everything not needed by HaltSwitch throws UnsupportedOperationException
 * rather than returning a plausible value: a double that quietly answers a
 * question nobody meant to ask it is how a test starts passing for the wrong
 * reason.
 */
final class HostilePath implements Path {

    /** What the provider does when asked to read THIS path's attributes. */
    enum OnRead { ENOENT, DIRECTORY, THROW_UNCHECKED }

    private final String name;
    private final HostilePath parent;
    final OnRead onRead;
    /** When set, getParent() throws this instead of answering. */
    RuntimeException parentThrow;

    /**
     * When set, toAbsolutePath() throws this instead of answering.
     *
     * An ERROR, not a RuntimeException, and that is the point: `catch
     * (Throwable)` and `catch (RuntimeException)` differ only here, and
     * Path.toAbsolutePath() is DOCUMENTED to throw java.io.IOError. It is the
     * one call in parentIsNotADirectory() whose javadoc names an Error, so it
     * is the honest input for the breadth of that clause rather than an
     * invented one.
     */
    Error absoluteThrow;

    HostilePath(String name, OnRead onRead, HostilePath parent) {
        this.name = name;
        this.onRead = onRead;
        this.parent = parent;
    }

    /** The unchecked failure a closed provider raises. Named rather than
     *  invented: it is one of the three HaltSwitch's own comment lists. */
    static RuntimeException unchecked() {
        return new java.nio.file.ClosedFileSystemException();
    }

    /** The Error a Path is documented to raise, for the one place a
     *  RuntimeException is not broad enough. */
    static Error ioError() {
        return new java.io.IOError(new IOException("the mount went away"));
    }

    @Override public Path getParent() {
        if (parentThrow != null) throw parentThrow;
        return parent;
    }

    @Override public FileSystem getFileSystem() { return FS; }
    @Override public boolean isAbsolute() { return true; }
    @Override public Path toAbsolutePath() {
        if (absoluteThrow != null) throw absoluteThrow;
        return this;
    }
    @Override public String toString() { return name; }

    // ---- everything HaltSwitch never touches ---------------------------
    private static UnsupportedOperationException no() {
        return new UnsupportedOperationException("HostilePath answers only what HaltSwitch asks");
    }
    @Override public Path getRoot() { throw no(); }
    @Override public Path getFileName() { throw no(); }
    @Override public int getNameCount() { throw no(); }
    @Override public Path getName(int i) { throw no(); }
    @Override public Path subpath(int a, int b) { throw no(); }
    @Override public boolean startsWith(Path other) { throw no(); }
    @Override public boolean endsWith(Path other) { throw no(); }
    @Override public Path normalize() { throw no(); }
    @Override public Path resolve(Path other) { throw no(); }
    @Override public Path relativize(Path other) { throw no(); }
    @Override public URI toUri() { throw no(); }
    @Override public Path toRealPath(LinkOption... options) { throw no(); }
    @Override public File toFile() { throw no(); }
    @Override public WatchKey register(WatchService w, WatchEvent.Kind<?>[] e,
                                       WatchEvent.Modifier... m) { throw no(); }
    @Override public int compareTo(Path other) { throw no(); }

    // ---- the filesystem and the provider behind it ---------------------

    static final FileSystem FS = new HostileFileSystem();
    static final FileSystemProvider PROVIDER = new HostileProvider();

    private static final class HostileFileSystem extends FileSystem {
        @Override public FileSystemProvider provider() { return PROVIDER; }
        @Override public void close() { }
        @Override public boolean isOpen() { return true; }
        @Override public boolean isReadOnly() { return true; }
        @Override public String getSeparator() { return "/"; }
        @Override public Iterable<Path> getRootDirectories() { throw no(); }
        @Override public Iterable<FileStore> getFileStores() { throw no(); }
        @Override public Set<String> supportedFileAttributeViews() { throw no(); }
        @Override public Path getPath(String first, String... more) { throw no(); }
        @Override public PathMatcher getPathMatcher(String s) { throw no(); }
        @Override public UserPrincipalLookupService getUserPrincipalLookupService() { throw no(); }
        @Override public WatchService newWatchService() { throw no(); }
    }

    private static final class HostileProvider extends FileSystemProvider {
        @Override public String getScheme() { return "hostile"; }

        /**
         * The one method HaltSwitch reaches, and the whole point of the class:
         * the path itself says what its own stat does.
         */
        @Override
        public <A extends BasicFileAttributes> A readAttributes(
                Path path, Class<A> type, LinkOption... options) throws IOException {
            HostilePath p = (HostilePath) path;
            switch (p.onRead) {
                case ENOENT:          throw new NoSuchFileException(p.toString());
                case THROW_UNCHECKED: throw unchecked();
                default:              break;
            }
            @SuppressWarnings("unchecked")
            A a = (A) DIRECTORY_ATTRS;
            return a;
        }

        @Override public FileSystem newFileSystem(URI uri, Map<String, ?> env) { throw no(); }
        @Override public FileSystem getFileSystem(URI uri) { throw no(); }
        @Override public Path getPath(URI uri) { throw no(); }
        @Override public SeekableByteChannel newByteChannel(Path p, Set<? extends OpenOption> o,
                                                            FileAttribute<?>... a) { throw no(); }
        @Override public DirectoryStream<Path> newDirectoryStream(Path d,
                                                                  DirectoryStream.Filter<? super Path> f) { throw no(); }
        @Override public void createDirectory(Path d, FileAttribute<?>... a) { throw no(); }
        @Override public void delete(Path p) { throw no(); }
        @Override public void copy(Path s, Path t, CopyOption... o) { throw no(); }
        @Override public void move(Path s, Path t, CopyOption... o) { throw no(); }
        @Override public boolean isSameFile(Path a, Path b) { throw no(); }
        @Override public boolean isHidden(Path p) { throw no(); }
        @Override public FileStore getFileStore(Path p) { throw no(); }
        @Override public void checkAccess(Path p, AccessMode... modes) { throw no(); }
        @Override public <V extends FileAttributeView> V getFileAttributeView(
                Path p, Class<V> type, LinkOption... o) { throw no(); }
        @Override public Map<String, Object> readAttributes(Path p, String attrs,
                                                            LinkOption... o) { throw no(); }
        @Override public void setAttribute(Path p, String a, Object v, LinkOption... o) { throw no(); }
    }

    /** A stat that says "directory", so the SUCCESS path is available too --
     *  a double that can only fail proves the guard fires, never that it stops
     *  firing when the question is answered. */
    private static final BasicFileAttributes DIRECTORY_ATTRS = new BasicFileAttributes() {
        public java.nio.file.attribute.FileTime lastModifiedTime() { throw no(); }
        public java.nio.file.attribute.FileTime lastAccessTime() { throw no(); }
        public java.nio.file.attribute.FileTime creationTime() { throw no(); }
        public boolean isRegularFile() { return false; }
        public boolean isDirectory() { return true; }
        public boolean isSymbolicLink() { return false; }
        public boolean isOther() { return false; }
        public long size() { return 0L; }
        public Object fileKey() { return null; }
    };
}
