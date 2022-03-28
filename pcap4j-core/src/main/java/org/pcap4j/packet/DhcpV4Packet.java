package org.pcap4j.packet;

import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;

public final class DhcpV4Packet extends AbstractPacket {

    /** DHCP MESSAGE FORMAT
     * Operation Code (1 byte)
     * HARDWARE TYPE (1 byte)
     * HARDWARE ADDRESS LENGTH (1 byte)
     * HOPS (1 byte)
     * TRANSACTION IDENTIFIER (xid) (4 bytes)
     * SECONDS (2 bytes)
     * FLAGS (2 bytes)
     *
     * CLIENT IP address (ciaddr) (4 bytes)
     * YOUR IP address (yiaddr) (4 bytes)
     * SERVER IP address (siaddr) (4 bytes)
     * GATEWAY IP address (giaddr) (4 bytes)
     * CLIENT HARDWARE address (chaddr) (16 bytes)
     * SERVER NAME (sname) (64 bytes)
     * file (128 bytes) (~Boot File Name)
     * options (variable size)
     * */

    private static final long serialVersionUID = 1111111111111L;

    private final DhcpV4Header header;


    public static DhcpV4Packet newPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException{
        ByteArrays.validateBounds(rawData, offset, length);
        return new DhcpV4Packet(rawData, offset, length);
    }

    private DhcpV4Packet(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        this.header = new DhcpV4Packet.DhcpV4Header(rawData, offset, length);
    }

    private DhcpV4Packet(Builder builder){
        if(builder == null
                || builder.operationCode == null
                || builder.hardwareType == null
                || builder.hops == null
                || builder.transactionIdentifier == null
                || builder.seconds == null
                || builder.flags == null
                || builder.ciaddr == null
                || builder.yiaddr == null
                || builder.giaddr == null
                || builder.chaddr == null
                || builder.sname == null
                || builder.file == null
                || builder.options == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("builder :")
                    .append(builder)
                    .append(" builder.operationCode: ")
                    .append(builder.operationCode)
                    .append(" builder.hardwareType: ")
                    .append(builder.hardwareType)
                    .append(" builder.hops: ")
                    .append(builder.hops)
                    .append(" builder.transactionIdentifier: ")
                    .append(builder.transactionIdentifier)
                    .append(" builder.seconds: ")
                    .append(builder.seconds)
                    .append(" builder.flags: ")
                    .append(builder.flags)
                    .append(" builder.ciaddr: ")
                    .append(builder.ciaddr)
                    .append(" builder.yiaddr: ")
                    .append(builder.yiaddr)
                    .append(" builder.giaddr: ")
                    .append(builder.giaddr)
                    .append(" builder.chaddr: ")
                    .append(builder.chaddr)
                    .append(" builder.sname: ")
                    .append(builder.sname)
                    .append(" builder.file: ")
                    .append(builder.file)
                    .append(" builder.options: ")
                    .append(builder.options);
            throw new NullPointerException(sb.toString());
        }
        this.header = new DhcpV4Header(builder);
    }

    @Override DhcpV4Header getHeader() {
        return header;
    }

    @Override Builder getBuilder() { return new Builder(this); }

    public static final class Builder extends AbstractBuilder{
        private byte operationCode;
        private byte hardwareType;
        private byte hardwareAddressLength;
        private Number hops;
        private byte transactionIdentifier;
        private Number seconds;
        private byte flags;
        private InetAddress ciaddr;
        private InetAddress yiaddr;
        private InetAddress siaddr;
        private InetAddress giaddr;
        private MacAddress chaddr;
        private byte sname;
        private byte file;
        private byte options;
    }

    public Builder() {}

    private Builder(DhcpV4Packet packet){
        this.operationCode = packet.header.operationCode;
        this.hardwareType = packet.header.hardwareType;
        this.hardwareAddressLength = packet.header.hardwareAddressLength;
        this.hops = packet.header.hops;
        this.transactionIdentifier = packet.header.transactionIdentifier;
        this.flags = packet.header.flags;
        this.ciaddr = packet.header.ciaddr;
        this.yiaddr = packet.header.yiaddr;
        this.siaddr = packet.header.siaddr;
        this.giaddr = packet.header.giaddr;
        this.chaddr = packet.header.chaddr;
        this.sname = packet.header.sname;
        this.file = packet.header.file;
        this.options = packet.header.options;
    }


    public static final class DhcpV4Header extends AbstractHeader {

    }
}
