package eu.exeris.caps.federatedlogin.internal.http;

import eu.exeris.kernel.spi.memory.LoanedBuffer;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * An on-heap implementation of {@link LoanedBuffer} backed by a {@link MemorySegment}.
 *
 * <p>Used for lightweight in-memory payload wrapping (such as ID tokens and HTTP request/response buffers)
 * within capability boundaries without requiring off-heap slab allocator coupling.
 *
 * @since 0.1.0
 */
public final class HeapLoanedBuffer implements LoanedBuffer {

    private final MemorySegment segment;
    private long size;

    public HeapLoanedBuffer(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes must not be null");
        this.segment = MemorySegment.ofArray(bytes);
        this.size = bytes.length;
    }

    private HeapLoanedBuffer(MemorySegment segment, long size) {
        this.segment = Objects.requireNonNull(segment, "segment must not be null");
        this.size = size;
    }

    public static HeapLoanedBuffer of(byte[] bytes) {
        return new HeapLoanedBuffer(bytes);
    }

    public static HeapLoanedBuffer of(String utf8Text) {
        Objects.requireNonNull(utf8Text, "utf8Text must not be null");
        return new HeapLoanedBuffer(utf8Text.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] readBytes(LoanedBuffer buffer) {
        if (buffer == null || buffer.size() == 0) {
            return new byte[0];
        }
        return buffer.segment().asSlice(0, buffer.size()).toArray(ValueLayout.JAVA_BYTE);
    }

    public static String readUtf8String(LoanedBuffer buffer) {
        byte[] bytes = readBytes(buffer);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    @Override
    public MemorySegment segment() {
        return segment;
    }

    @Override
    public long size() {
        return size;
    }

    @Override
    public long capacity() {
        return segment.byteSize();
    }

    @Override
    public LoanedBuffer slice(long offset, long length) {
        byte[] slice = segment.asSlice(offset, length).toArray(ValueLayout.JAVA_BYTE);
        return new HeapLoanedBuffer(slice);
    }

    @Override
    public LoanedBuffer view() {
        byte[] bytes = segment.asSlice(0, size).toArray(ValueLayout.JAVA_BYTE);
        return new HeapLoanedBuffer(bytes);
    }

    @Override
    public LoanedBuffer peek(long offset, long length) {
        return slice(offset, length);
    }

    @Override
    public void retain() {
        // No-op: heap buffer has no reference-counted slab allocation
    }

    @Override
    public void close() {
        // No-op: heap memory managed by JVM garbage collection
    }

    @Override
    public int refCount() {
        return 1;
    }

    @Override
    public void setSize(long newSize) {
        if (newSize < 0 || newSize > capacity()) {
            throw new IllegalArgumentException("newSize out of bounds: " + newSize);
        }
        this.size = newSize;
    }

    @Override
    public boolean isAlive() {
        return true;
    }

    @Override
    public void addCloseAction(Runnable action) {
        // No-op: no pooled resources to release
    }
}
