// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// TraceEvent reads synchronously. Preserve exactly the bytes it consumes so the
// Go decoder can later replay the same session as the managed reference reader.
sealed class RecordingStream(Stream source, Stream recording) : Stream
{
    public override int Read(byte[] buffer, int offset, int count)
    {
        int read = source.Read(buffer, offset, count);
        recording.Write(buffer, offset, read);
        return read;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => recording.Flush();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
