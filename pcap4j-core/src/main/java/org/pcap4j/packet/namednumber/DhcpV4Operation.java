package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

public class DhcpV4Operation extends NamedNumber<Short, DhcpV4Operation> {
    public static final DhcpV4Operation REQUEST = new DhcpV4Operation((short) 1, "Request");
    public static final DhcpV4Operation REPLY = new DhcpV4Operation((short) 1, "Reply");

    private static final Map<Short, DhcpV4Operation> registry = new HashMap<Short, DhcpV4Operation>(30);

    static{
        registry.put(REQUEST.value(), REQUEST);
        registry.put(REPLY.value(), REPLY);
    }

    public DhcpV4Operation(Short value, String name) {
        super(value, name);
    }

    public static DhcpV4Operation getInstance(Short value) {
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
