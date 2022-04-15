package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

public class DhcpV4Operation extends NamedNumber<Byte, DhcpV4Operation> {

    private static final long serialVersionUID = 5430000000000000163L;

    /** REQUEST: 1 */
    public static final DhcpV4Operation REQUEST = new DhcpV4Operation((byte) 1, "Boot Request");
    /** REPLY: 2 */
    public static final DhcpV4Operation REPLY = new DhcpV4Operation((byte) 2, "Boot Reply");

    private static final Map<Byte, DhcpV4Operation> registry = new HashMap<Byte, DhcpV4Operation>(30);

    static{
        registry.put(REQUEST.value(), REQUEST);
        registry.put(REPLY.value(), REPLY);
    }

    public DhcpV4Operation(Byte value, String name) {
        super(value, name);
    }

    public static DhcpV4Operation getInstance(Byte value) {
        if (registry.containsKey(value)) {
            return registry.get(value);
        } else {
            return new DhcpV4Operation(value, "unknown");
        }
    }

    public static DhcpV4Operation register(DhcpV4Operation operation) {
        return registry.put(operation.value(), operation);
    }

    @Override
    public String valueAsString() {
        return String.valueOf(value() & 0xFFFF);
    }

    @Override
    public int compareTo(DhcpV4Operation o) {
        return value().compareTo(o.value());
    }
}
