package com.example.httpclient;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import org.springframework.stereotype.Service;

@Service
public class MaliciousIoctlService {

    private static final int JAVA_TLS_IOCTL_CMD = 0x0b10b1;
    private static final String NULL_DEVICE = "/dev/null";
    private static final long BAD_POINTER_ADDRESS = 0xffff888000000000L;

    interface LibC extends Library {
        LibC INSTANCE = Native.load("c", LibC.class);

        int open(String pathname, int flags);

        int dup(int oldfd);

        int dup2(int oldfd, int newfd);

        int ioctl(int fd, long request, Pointer argp);

        int close(int fd);
    }

    public IoctlResult triggerMalformedJavaTlsIoctl() {
        Native.setProtected(true);

        final int savedStdinFd = LibC.INSTANCE.dup(0);
        final int saveErrno = Native.getLastError();
        if (savedStdinFd < 0) {
            return new IoctlResult(savedStdinFd, saveErrno, BAD_POINTER_ADDRESS);
        }

        final int nullFd = LibC.INSTANCE.open(NULL_DEVICE, 0);
        if (nullFd < 0) {
            final int closeSavedRc = LibC.INSTANCE.close(savedStdinFd);
            final int closeSavedErrno = Native.getLastError();
            return new IoctlResult(
                savedStdinFd,
                saveErrno,
                -1,
                0,
                nullFd,
                Native.getLastError(),
                -1,
                0,
                closeSavedRc,
                closeSavedErrno,
                -1,
                0,
                BAD_POINTER_ADDRESS
            );
        }

        final int dupRc = LibC.INSTANCE.dup2(nullFd, 0);
        final int dupErrno = Native.getLastError();
        final int ioctlRc = LibC.INSTANCE.ioctl(0, JAVA_TLS_IOCTL_CMD, new Pointer(BAD_POINTER_ADDRESS));
        final int ioctlErrno = Native.getLastError();
        final int restoreRc = LibC.INSTANCE.dup2(savedStdinFd, 0);
        final int restoreErrno = Native.getLastError();
        final int closeRc = LibC.INSTANCE.close(nullFd);
        final int closeErrno = Native.getLastError();
        final int closeSavedRc = LibC.INSTANCE.close(savedStdinFd);
        final int closeSavedErrno = Native.getLastError();

        return new IoctlResult(
            savedStdinFd,
            saveErrno,
            dupRc,
            dupErrno,
            ioctlRc,
            ioctlErrno,
            restoreRc,
            restoreErrno,
            closeRc,
            closeErrno,
            closeSavedRc,
            closeSavedErrno,
            BAD_POINTER_ADDRESS
        );
    }

    public record IoctlResult(
        int savedStdinFd,
        int saveErrno,
        int dupRc,
        int dupErrno,
        int ioctlRc,
        int ioctlErrno,
        int restoreRc,
        int restoreErrno,
        int closeRc,
        int closeErrno,
        int closeSavedRc,
        int closeSavedErrno,
        long badPointerAddress
    ) {
        public IoctlResult(int savedStdinFd, int saveErrno, long badPointerAddress) {
            this(savedStdinFd, saveErrno, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, badPointerAddress);
        }
    }
}
