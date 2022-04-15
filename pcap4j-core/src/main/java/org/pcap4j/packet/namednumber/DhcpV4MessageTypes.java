package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

public class DhcpV4MessageTypes extends NamedNumber<Short, DhcpV4MessageTypes> {
    /** DISCOVER: 1 */
    public static final DhcpV4MessageTypes DISCOVER = new DhcpV4MessageTypes((short) 1, "DISCOVER");

    /** OFFER: 2 */
    public static final DhcpV4MessageTypes OFFER = new DhcpV4MessageTypes((short) 2, "OFFER");

    /** REQUEST: 3 */
    public static final DhcpV4MessageTypes REQUEST = new DhcpV4MessageTypes((short) 3, "REQUEST");

    /** DECLINE: 4 */
    public static final DhcpV4MessageTypes DECLINE = new DhcpV4MessageTypes((short) 4, "DECLINE");

    /** ACKNOWLEDGEMENT (ACK): 5 */
    public static final DhcpV4MessageTypes ACK = new DhcpV4MessageTypes((short) 5, "ACKNOWLEDGE");

    /** DHCP NEGATIVE ACKNOWLEDGEMENT (NAK): 6 */
    public static final DhcpV4MessageTypes NAK = new DhcpV4MessageTypes((short) 6, "NAK");

    /** Release: 7 */
    public static final DhcpV4MessageTypes RELEASE = new DhcpV4MessageTypes((short) 7, "RELEASE");

    /** Inform: 8 */
    public static final DhcpV4MessageTypes INFORM = new DhcpV4MessageTypes((short) 8, "INFORM");

    /** Force Renew: 9 */
    public static final DhcpV4MessageTypes FORCE_RENEW = new DhcpV4MessageTypes((short) 9, "FORCE RENEW");

    /** Lease query: 10 */
    public static final DhcpV4MessageTypes LEASE_QUERY = new DhcpV4MessageTypes((short) 10, "LEASE QUERY");

    /** Lease Unassigned: 11 */
    public static final DhcpV4MessageTypes LEASE_UNASSIGNED = new DhcpV4MessageTypes((short) 11, "LEASE UNASSIGNED");

    /** Lease Unknown: 12 */
    public static final DhcpV4MessageTypes LEASE_UNKNOWN = new DhcpV4MessageTypes((short) 12, "LEASE UNKNOWN");

    /** Lease Active: 13 */
    public static final DhcpV4MessageTypes LEASE_ACTIVE = new DhcpV4MessageTypes((short) 13, "LEASE ACTIVE");

    /** Bulk Lease Query: 14 */
    public static final DhcpV4MessageTypes BULK_LEASE_QUERY = new DhcpV4MessageTypes((short) 14, "BULK LEASE QUERY");

    /** Lease Query Done: 15 */
    public static final DhcpV4MessageTypes LEASE_QUERY_DONE = new DhcpV4MessageTypes((short) 15, "LEASE QUERY DONE");

    /** Active Lease Query: 16 */
    public static final DhcpV4MessageTypes ACTIVE_LEASE_QUERY = new DhcpV4MessageTypes((short) 16, "ACTIVE LEASE QUERY");

    /** Lease Query Status: 17 */
    public static final DhcpV4MessageTypes LEASE_QUERY_STATUS = new DhcpV4MessageTypes((short) 17, "LEASE QUERY STATUS");

    /** TLS: 18 */
    public static final DhcpV4MessageTypes TLS = new DhcpV4MessageTypes((short) 18, "TLS");

    private static final Map<Short, DhcpV4MessageTypes> registry = new HashMap<Short, DhcpV4MessageTypes>(30);

    static{
        registry.put(DISCOVER.value(), DISCOVER);
        registry.put(OFFER.value(), OFFER);
        registry.put(REQUEST.value(), REQUEST);
        registry.put(DECLINE.value(), DECLINE);
        registry.put(ACK.value(), ACK);
        registry.put(NAK.value(), NAK);
        registry.put(RELEASE.value(), RELEASE);
        registry.put(INFORM.value(), INFORM);
        registry.put(FORCE_RENEW.value(), FORCE_RENEW);
        registry.put(LEASE_QUERY.value(), LEASE_QUERY);
        registry.put(LEASE_UNASSIGNED.value(), LEASE_UNASSIGNED);
        registry.put(LEASE_UNKNOWN.value(), LEASE_UNKNOWN);
        registry.put(LEASE_ACTIVE.value(), LEASE_ACTIVE);
        registry.put(BULK_LEASE_QUERY.value(), BULK_LEASE_QUERY);
        registry.put(LEASE_QUERY_DONE.value(), LEASE_QUERY_DONE);
        registry.put(ACTIVE_LEASE_QUERY.value(), ACTIVE_LEASE_QUERY);
        registry.put(LEASE_QUERY_STATUS.value(), LEASE_QUERY_STATUS);
        registry.put(TLS.value(), TLS);
    }

    public DhcpV4MessageTypes(Short value, String name) {
        super(value, name);
    }

    public static DhcpV4MessageTypes getInstance(Short value) {
        if (registry.containsKey(value)) {
            return registry.get(value);
        } else {
            return new DhcpV4MessageTypes(value, "unknown");
        }
    }

    public static DhcpV4MessageTypes register(DhcpV4MessageTypes messageType) {
        return registry.put(messageType.value(), messageType);
    }

    @Override
    public String valueAsString() {
        return String.valueOf(value() & 0xFFFF);
    }

    @Override
    public int compareTo(DhcpV4MessageTypes o) {
        return value().compareTo(o.value());
    }
}
