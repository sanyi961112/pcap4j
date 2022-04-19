package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

public class DhcpV6MessageTypes extends NamedNumber<Byte, DhcpV6MessageTypes> {
  /** SOLICIT: 1 */
  public static final DhcpV6MessageTypes SOLICIT = new DhcpV6MessageTypes((byte) 1, "SOLICIT");
  /** ADVERTISE: 2 */
  public static final DhcpV6MessageTypes ADVERTISE = new DhcpV6MessageTypes((byte) 2, "ADVERTISE");
  /** REQUEST: 3 */
  public static final DhcpV6MessageTypes REQUEST = new DhcpV6MessageTypes((byte) 3, "REQUEST");
  /** CONFIRM: 4 */
  public static final DhcpV6MessageTypes CONFIRM = new DhcpV6MessageTypes((byte) 4, "CONFIRM");
  /** RENEW: 5 */
  public static final DhcpV6MessageTypes RENEW = new DhcpV6MessageTypes((byte) 5, "RENEW");
  /** REBIND: 6 */
  public static final DhcpV6MessageTypes REBIND = new DhcpV6MessageTypes((byte) 6, "REBIND");
  /** REPLY: 7 */
  public static final DhcpV6MessageTypes REPLY = new DhcpV6MessageTypes((byte) 7, "REPLY");
  /** RELEASE: 8 */
  public static final DhcpV6MessageTypes RELEASE = new DhcpV6MessageTypes((byte) 8, "RELEASE");
  /** DECLINE: 9 */
  public static final DhcpV6MessageTypes DECLINE = new DhcpV6MessageTypes((byte) 9, "DECLINE");
  /** RECONFIGURE: 10 */
  public static final DhcpV6MessageTypes RECONFIGURE = new DhcpV6MessageTypes((byte) 10, "RECONFIGURE");
  /** INFORMATION-REQUEST: 11 */
  public static final DhcpV6MessageTypes INFORMATION_REQUEST = new DhcpV6MessageTypes((byte) 11, "INFORMATION-REQUEST");
  /** RELAY-FORW: 12 */
  public static final DhcpV6MessageTypes RELAY_FORW = new DhcpV6MessageTypes((byte) 12, "RELAY-FORW");
  /** RELAY-REPL: 13 */
  public static final DhcpV6MessageTypes RELAY_REPL = new DhcpV6MessageTypes((byte) 13, "RELAY-REPL");
  /** LEASEQUERY: 14 */
  public static final DhcpV6MessageTypes LEASEQUERY = new DhcpV6MessageTypes((byte) 14, "LEASEQUERY");
  /** LEASEQUERY-REPLY: 15 */
  public static final DhcpV6MessageTypes LEASEQUERY_REPLY = new DhcpV6MessageTypes((byte) 15, "LEASEQUERY-REPLY");
  /** LEASEQUERY-DONE: 16 */
  public static final DhcpV6MessageTypes LEASEQUERY_DONE = new DhcpV6MessageTypes((byte) 16, "LEASEQUERY-DONE");
  /** LEASEQUERY–DATA: 17 */
  public static final DhcpV6MessageTypes LEASEQUERY_DATA = new DhcpV6MessageTypes((byte) 17, "LEASEQUERY–DATA");
  /** RECONFIGURE-REQUEST: 18 */
  public static final DhcpV6MessageTypes RECONFIGURE_REQUEST = new DhcpV6MessageTypes((byte) 18, "RECONFIGURE-REQUEST");
  /** RECONFIGURE-REPLY: 19 */
  public static final DhcpV6MessageTypes RECONFIGURE_REPLY = new DhcpV6MessageTypes((byte) 19, "RECONFIGURE-REPLY");
  /** DHCPV4-QUERY: 20 */
  public static final DhcpV6MessageTypes DHCPV4_QUERY = new DhcpV6MessageTypes((byte) 20, "DHCPV4-QUERY");
  /** DHCPV4-RESPONSE: 21 */
  public static final DhcpV6MessageTypes DHCPV4_RESPONSE = new DhcpV6MessageTypes((byte) 21, "DHCPV4-RESPONSE");
  /** ACTIVELEASEQUERY: 22 */
  public static final DhcpV6MessageTypes ACTIVELEASEQUERY = new DhcpV6MessageTypes((byte) 22, "ACTIVELEASEQUERY");
  /** STARTTLS: 23 */
  public static final DhcpV6MessageTypes STARTTLS = new DhcpV6MessageTypes((byte) 23, "STARTTLS");
  /** BNDUPD: 24 */
  public static final DhcpV6MessageTypes BNDUPD = new DhcpV6MessageTypes((byte) 24, "BNDUPD");
  /** BNDREPLY: 25 */
  public static final DhcpV6MessageTypes BNDREPLY = new DhcpV6MessageTypes((byte) 25, "BNDREPLY");
  /** POOLREQ: 26 */
  public static final DhcpV6MessageTypes POOLREQ = new DhcpV6MessageTypes((byte) 26, "POOLREQ");
  /** POOLRESP: 27 */
  public static final DhcpV6MessageTypes POOLRESP = new DhcpV6MessageTypes((byte) 27, "POOLRESP");
  /** UPDREQ: 28 */
  public static final DhcpV6MessageTypes UPDREQ = new DhcpV6MessageTypes((byte) 28, "UPDREQ");
  /** UPDREQALL: 29 */
  public static final DhcpV6MessageTypes UPDREQALL = new DhcpV6MessageTypes((byte) 29, "UPDREQALL");
  /** UPDDONE: 30 */
  public static final DhcpV6MessageTypes UPDDONE = new DhcpV6MessageTypes((byte) 30, "UPDDONE");
  /** CONNECT: 31 */
  public static final DhcpV6MessageTypes CONNECT = new DhcpV6MessageTypes((byte) 31, "CONNECT");
  /** CONNECTREPLY: 32 */
  public static final DhcpV6MessageTypes CONNECTREPLY = new DhcpV6MessageTypes((byte) 32, "CONNECTREPLY");
  /** DISCONNECT: 33 */
  public static final DhcpV6MessageTypes DISCONNECT = new DhcpV6MessageTypes((byte) 33, "DISCONNECT");
  /** STATE: 34 */
  public static final DhcpV6MessageTypes STATE = new DhcpV6MessageTypes((byte) 34, "STATE");
  /** CONTACT: 35 */
  public static final DhcpV6MessageTypes CONTACT = new DhcpV6MessageTypes((byte) 35, "CONTACT");
  /** 36-255 Unassigned*/
  private static final Map<Byte, DhcpV6MessageTypes> registry = new HashMap<Byte, DhcpV6MessageTypes>(30);

  static{
    registry.put(SOLICIT.value(), SOLICIT);
    registry.put(ADVERTISE.value(), ADVERTISE);
    registry.put(REQUEST.value(), REQUEST);
    registry.put(CONFIRM.value(), CONFIRM);
    registry.put(RENEW.value(), RENEW);
    registry.put(REBIND.value(), REBIND);
    registry.put(REPLY.value(), REPLY);
    registry.put(RELEASE.value(), RELEASE);
    registry.put(DECLINE.value(), DECLINE);
    registry.put(RECONFIGURE.value(), RECONFIGURE);
    registry.put(INFORMATION_REQUEST.value(), INFORMATION_REQUEST);
    registry.put(RELAY_FORW.value(), RELAY_FORW);
    registry.put(RELAY_REPL.value(), RELAY_REPL);
    registry.put(LEASEQUERY.value(), LEASEQUERY);
    registry.put(LEASEQUERY_REPLY.value(), LEASEQUERY_REPLY);
    registry.put(LEASEQUERY_DONE.value(), LEASEQUERY_DONE);
    registry.put(LEASEQUERY_DATA.value(), LEASEQUERY_DATA);
    registry.put(RECONFIGURE_REQUEST.value(), RECONFIGURE_REQUEST);
    registry.put(RECONFIGURE_REPLY.value(), RECONFIGURE_REPLY);
    registry.put(DHCPV4_QUERY.value(), DHCPV4_QUERY);
    registry.put(DHCPV4_RESPONSE.value(), DHCPV4_RESPONSE);
    registry.put(ACTIVELEASEQUERY.value(), ACTIVELEASEQUERY);
    registry.put(STARTTLS.value(), STARTTLS);
    registry.put(BNDUPD.value(), BNDUPD);
    registry.put(BNDREPLY.value(), BNDREPLY);
    registry.put(POOLREQ.value(), POOLREQ);
    registry.put(POOLRESP.value(), POOLRESP);
    registry.put(UPDREQ.value(), UPDREQ);
    registry.put(UPDREQALL.value(), UPDREQALL);
    registry.put(UPDDONE.value(), UPDDONE);
    registry.put(CONNECT.value(), CONNECT);
    registry.put(CONNECTREPLY.value(), CONNECTREPLY);
    registry.put(DISCONNECT.value(), DISCONNECT);
    registry.put(STATE.value(), STATE);
    registry.put(CONTACT.value(), CONTACT);
  }

  public DhcpV6MessageTypes(Byte value, String name) {
    super(value, name);
  }

  public static DhcpV6MessageTypes getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new DhcpV6MessageTypes(value, "unknown");
    }
  }

  public static DhcpV6MessageTypes register(DhcpV6MessageTypes messageType) {
    return registry.put(messageType.value(), messageType);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFFFF);
  }

  @Override
  public int compareTo(DhcpV6MessageTypes o) {
    return value().compareTo(o.value());
  }
}
