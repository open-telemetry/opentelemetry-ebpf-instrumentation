// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

import java.io.IOException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicInteger;
import org.jpos.core.ConfigurationException;
import org.jpos.core.SimpleConfiguration;
import org.jpos.iso.BaseChannel;
import org.jpos.iso.ISOException;
import org.jpos.iso.ISOMsg;
import org.jpos.iso.ISOServer;
import org.jpos.iso.ISOSource;
import org.jpos.iso.ServerChannel;
import org.jpos.iso.channel.ASCIIChannel;
import org.jpos.iso.channel.NACChannel;
import org.jpos.iso.packager.ISO87APackager;
import org.jpos.iso.packager.ISO87BPackager;

/**
 * Switch and acquirer built on jPOS, so OBI is checked against an independent ISO 8583
 * implementation instead of hand-built frames.
 *
 * <ul>
 *   <li>ISO87A (ASCII MTI and hex bitmap) with a 2-byte binary length header on port 8584
 *   <li>ISO87B (BCD MTI and binary bitmap) with a 4-byte ASCII length header on port 8585
 * </ul>
 */
public final class IsoSwitch {
  private static final String HOST = "127.0.0.1";
  private static final int ASCII_PORT = 8584;
  private static final int BINARY_PORT = 8585;
  private static final byte[] NO_TPDU = new byte[0];
  private static final long EXCHANGE_INTERVAL_MS = 1000;
  private static final int EXCHANGE_TIMEOUT_MS = 5000;
  private static final int MAX_SESSIONS = 100;

  private static final String APPROVED = "00";
  private static final String DECLINED = "05";
  private static final String TECHNICAL_ERROR = "91";

  private static final String AMOUNT_DECLINED = "000000000500";
  private static final String AMOUNT_TECHNICAL_ERROR = "000000000900";
  private static final String AMOUNT_APPROVED = "000000001000";

  private static final DateTimeFormatter TRANSMISSION_TIME =
      DateTimeFormatter.ofPattern("MMddHHmmss");

  private static final AtomicInteger STAN = new AtomicInteger();

  private IsoSwitch() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 1) {
      throw new IllegalArgumentException("Expected a role of switch or client");
    }
    switch (args[0]) {
      case "switch" -> {
        startServer(ASCII_PORT, new NACChannel(new ISO87APackager(), NO_TPDU));
        startServer(BINARY_PORT, new ASCIIChannel(new ISO87BPackager()));
      }
      case "client" -> {
        while (true) {
          runExchanges();
          Thread.sleep(EXCHANGE_INTERVAL_MS);
        }
      }
      default -> throw new IllegalArgumentException("Unknown role " + args[0]);
    }
  }

  private static void startServer(int port, ServerChannel channel)
      throws ConfigurationException {
    ISOServer server = new ISOServer(port, channel, MAX_SESSIONS);
    // An empty configuration makes ISOServer create its session executor.
    server.setConfiguration(new SimpleConfiguration());
    server.addISORequestListener(IsoSwitch::respond);

    new Thread(server, "iso-server-" + port).start();
  }

  private static boolean respond(ISOSource source, ISOMsg request) {
    try {
      ISOMsg response = (ISOMsg) request.clone();
      response.setResponseMTI();
      if (request.hasField(4)) {
        response.set(39, responseCode(request.getString(4)));
      }
      source.send(response);
    } catch (ISOException | IOException e) {
      System.err.println("cannot answer " + request.getString(0) + ": " + e);
    }
    return true;
  }

  private static String responseCode(String amount) {
    return switch (amount) {
      case AMOUNT_DECLINED -> DECLINED;
      case AMOUNT_TECHNICAL_ERROR -> TECHNICAL_ERROR;
      default -> APPROVED;
    };
  }

  private static void runExchanges() {
    try {
      exchange(asciiChannel(), networkManagement());
      exchange(asciiChannel(), authorization(AMOUNT_DECLINED));
      exchange(asciiChannel(), authorization(AMOUNT_TECHNICAL_ERROR));
      exchange(binaryChannel(), financial());
    } catch (ISOException | IOException e) {
      System.err.println("exchange failed: " + e);
    }
  }

  private static BaseChannel asciiChannel() {
    return new NACChannel(HOST, ASCII_PORT, new ISO87APackager(), NO_TPDU);
  }

  private static BaseChannel binaryChannel() {
    return new ASCIIChannel(HOST, BINARY_PORT, new ISO87BPackager());
  }

  private static void exchange(BaseChannel channel, ISOMsg request)
      throws IOException, ISOException {
    channel.setTimeout(EXCHANGE_TIMEOUT_MS);
    channel.connect();
    try {
      channel.send(request);
      channel.receive();
    } finally {
      channel.disconnect();
    }
  }

  private static ISOMsg networkManagement() throws ISOException {
    ISOMsg msg = baseMessage("0800");
    msg.set(70, "301");
    return msg;
  }

  private static ISOMsg authorization(String amount) throws ISOException {
    ISOMsg msg = baseMessage("0100");
    msg.set(2, "4111111111111111");
    msg.set(3, "000000");
    msg.set(4, amount);
    return msg;
  }

  private static ISOMsg financial() throws ISOException {
    ISOMsg msg = baseMessage("0200");
    msg.set(2, "4111111111111111");
    msg.set(3, "000000");
    msg.set(4, AMOUNT_APPROVED);
    msg.set(37, "000000000001");
    msg.set(41, "TERM0001");
    msg.set(49, "840");
    return msg;
  }

  private static ISOMsg baseMessage(String mti) throws ISOException {
    ISOMsg msg = new ISOMsg(mti);
    msg.set(7, ZonedDateTime.now(ZoneOffset.UTC).format(TRANSMISSION_TIME));
    msg.set(11, String.format("%06d", STAN.incrementAndGet() % 1_000_000));
    return msg;
  }
}
