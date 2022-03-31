package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

public final class DhcpV4Packet extends AbstractPacket {


    private final DhcpV4Header header;


    public static DhcpV4Packet newPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new DhcpV4Packet(rawData, offset, length);
    }

    private DhcpV4Packet(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        this.header = new DhcpV4Header(rawData, offset, length);
    }

    private DhcpV4Packet(Builder builder) {
        if (builder == null
//                || builder.operationCode == null
//                || builder.hardwareType == null
                || builder.hops == null
//                || builder.transactionIdentifier == null
                || builder.seconds == null
//                || builder.flags == null
                || builder.ciaddr == null
                || builder.yiaddr == null
                || builder.giaddr == null
                || builder.chaddr == null
//                || builder.sname == null
//                || builder.file == null
            /*  || builder.options == null*/) {
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

    @Override
    public DhcpV4Header getHeader() {
        return header;
    }

    @Override
    public Builder getBuilder() {
        return new Builder(this);
    }

    public static final class Builder extends AbstractBuilder {

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


        public Builder() {
        }

        private Builder(DhcpV4Packet packet) {
            this.operationCode = (byte) packet.header.operationCode;
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
            this.options = (byte) packet.header.options;
        }

        public Builder operationCode(byte operation) {
            this.operationCode = operationCode;
            return this;
        }

        public Builder hardwareType(byte hardwareType) {
            this.hardwareType = hardwareType;
            return this;
        }

        public Builder hardwareAddressLength(byte hardwareAddressLength) {
            this.hardwareAddressLength = hardwareAddressLength;
            return this;
        }

        public Builder hops(byte hops) {
            this.hops = hops;
            return this;
        }

        public Builder transactionIdentifier(byte transactionIdentifier) {
            this.transactionIdentifier = transactionIdentifier;
            return this;
        }

        public Builder flags(byte flags) {
            this.flags = flags;
            return this;
        }

        public Builder ciaddr(InetAddress ciaddr) {
            this.ciaddr = ciaddr;
            return this;
        }

        public Builder yiaddr(InetAddress yiaddr) {
            this.yiaddr = yiaddr;
            return this;
        }

        public Builder siaddr(InetAddress siaddr) {
            this.siaddr = siaddr;
            return this;
        }

        public Builder giaddr(InetAddress giaddr) {
            this.giaddr = giaddr;
            return this;
        }

        public Builder chaddr(MacAddress chaddr) {
            this.chaddr = chaddr;
            return this;
        }

        public Builder sname(byte sname) {
            this.sname = sname;
            return this;
        }

        public Builder file(byte file) {
            this.file = file;
            return this;
        }

        public Builder options(byte options) {
            this.options = options;
            return this;
        }


        @Override
        public DhcpV4Packet build() {
            return new DhcpV4Packet(this);
        }
    }

    /**
     * DhcpV4Header
     */
    public static final class DhcpV4Header extends AbstractHeader {
        private static final long serialVersionUID = -6744946102881067232L;

        /*(D)iscover, (R)equest, (O)ffer and (A)cknowledge*/
        /**
         * DHCPv4 MESSAGE FORMAT
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
         * FILE (~Boot File Name) (128 bytes)
         * OPTIONS (variable size) (Array?)
         */
        /**
         * TODO fix byte sizes and get something for the options size
         */
        private static final int OPERATION_CODE_OFFSET = 0;
        private static final int OPERATION_CODE_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int HARDWARE_TYPE_OFFSET = OPERATION_CODE_OFFSET + OPERATION_CODE_SIZE;
        private static final int HARDWARE_TYPE_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int HW_ADDRESS_LENGTH_OFFSET = HARDWARE_TYPE_OFFSET + HARDWARE_TYPE_SIZE;
        private static final int HW_ADDRESS_LENGTH_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int HOPS_OFFSET = HW_ADDRESS_LENGTH_OFFSET + HW_ADDRESS_LENGTH_SIZE;
        private static final int HOPS_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int TRANSACTION_IDENTIFIER_OFFSET = HOPS_OFFSET + HOPS_SIZE;
        private static final int TRANSACTION_IDENTIFIER_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int SECONDS_OFFSET = TRANSACTION_IDENTIFIER_OFFSET + TRANSACTION_IDENTIFIER_SIZE;
        private static final int SECONDS_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int FLAGS_OFFSET = SECONDS_OFFSET + SECONDS_SIZE;
        private static final int FLAGS_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int CIADDR_OFFSET = FLAGS_OFFSET + FLAGS_SIZE;
        private static final int CIADDR_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int YIADDR_OFFSET = CIADDR_OFFSET + CIADDR_SIZE;
        private static final int YIADDR_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int SIADDR_OFFSET = YIADDR_OFFSET + YIADDR_SIZE;
        private static final int SIADDR_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int GIADDR_OFFSET = SIADDR_OFFSET + SIADDR_SIZE;
        private static final int GIADDR_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int CHADDR_OFFSET = GIADDR_OFFSET + GIADDR_SIZE;
        private static final int CHADDR_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int SNAME_OFFSET = CHADDR_OFFSET + CHADDR_SIZE;
        private static final int SNAME_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int FILE_OFFSET = SNAME_OFFSET + SNAME_SIZE;
        private static final int FILE_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int OPTIONS_OFFSET = FILE_OFFSET + FILE_SIZE;
        private static final int OPTIONS_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int DHCP_HEADER_SIZE = OPTIONS_OFFSET + OPTIONS_SIZE;

        private final Number operationCode;
        private final byte hardwareType;
        private final byte hardwareAddressLength;
        private final Number hops;
        private final byte transactionIdentifier;
        private final Number seconds;
        private final byte flags;
        private final InetAddress ciaddr;
        private final InetAddress yiaddr;
        private final InetAddress siaddr;
        private final InetAddress giaddr;
        private final MacAddress chaddr;
        private final byte sname;
        private final byte file;
        private final short options;

        private DhcpV4Header(byte[] rawData, int offset, int length) throws IllegalRawDataException {
            if (length < DHCP_HEADER_SIZE) {
                StringBuilder sb = new StringBuilder(200);
                sb.append("The data is too short to build a DHCP header")
                        .append(DHCP_HEADER_SIZE)
                        .append(" bytes). data: ")
                        .append(ByteArrays.toHexString(rawData, " "))
                        .append(", offset: ")
                        .append(offset)
                        .append(", length: ")
                        .append(length);
                throw new IllegalRawDataException(sb.toString());
            }

            this.operationCode = ByteArrays.getShort(rawData, OPERATION_CODE_OFFSET + offset);
            this.hardwareType = ByteArrays.getByte(rawData, HARDWARE_TYPE_OFFSET + offset);
            this.hardwareAddressLength = ByteArrays.getByte(
                    rawData, HW_ADDRESS_LENGTH_OFFSET + offset
            );
            this.hops = ByteArrays.getShort(rawData, HOPS_OFFSET + offset);
            this.transactionIdentifier = ByteArrays.getByte(rawData, TRANSACTION_IDENTIFIER_OFFSET + offset);
            this.seconds = ByteArrays.getShort(rawData, SECONDS_OFFSET + offset);
            this.flags = ByteArrays.getByte(rawData, FLAGS_OFFSET + offset);
            this.ciaddr = ByteArrays.getInet4Address(rawData, CIADDR_OFFSET + offset);
            this.yiaddr = ByteArrays.getInet4Address(rawData, YIADDR_OFFSET + offset);
            this.siaddr = ByteArrays.getInet4Address(rawData, SIADDR_OFFSET + offset);
            this.giaddr = ByteArrays.getInet4Address(rawData, GIADDR_OFFSET + offset);
            this.chaddr = ByteArrays.getMacAddress(rawData, CHADDR_OFFSET + offset);
            this.sname = ByteArrays.getByte(rawData, SNAME_OFFSET + offset);
            this.file = ByteArrays.getByte(rawData, FILE_OFFSET + offset);
            this.options = ByteArrays.getShort(rawData, OPTIONS_OFFSET + offset);


        }

        private DhcpV4Header(Builder builder) {
            this.operationCode = builder.operationCode;
            this.hardwareType = builder.hardwareType;
            this.hardwareAddressLength = builder.hardwareAddressLength;
            this.hops = builder.hops;
            this.transactionIdentifier = builder.transactionIdentifier;
            this.seconds = builder.seconds;
            this.flags = builder.flags;
            this.ciaddr = builder.ciaddr;
            this.yiaddr = builder.yiaddr;
            this.siaddr = builder.siaddr;
            this.giaddr = builder.giaddr;
            this.chaddr = builder.chaddr;
            this.sname = builder.sname;
            this.file = builder.file;
            this.options = builder.options;
        }

        /*Getters*/
        public byte getOperationCode() { return (byte) operationCode; }
        public byte getHardwareType() { return hardwareType; }
        public byte getHardwareAddressLength() { return hardwareAddressLength; }
        public byte getHops() { return (byte) hops; }
        public byte getTransactionIdentifier() { return (byte) transactionIdentifier; }
        public byte getSeconds() { return (byte) seconds; }
        public byte getFlags() { return (byte) flags; }
        public InetAddress getCiaddr() { return ciaddr; }
        public InetAddress getYiaddr() { return yiaddr; }
        public InetAddress getSiaddr() { return siaddr; }
        public InetAddress getGiaddr() { return giaddr; }
        public MacAddress getChaddr() { return chaddr; }
        public byte getSname() { return  sname; }
        public byte getFile() { return file; }
        public byte getOptions() { return (byte) options; }

        @Override
        protected List<byte[]> getRawFields() {
            List<byte[]> rawFields = new ArrayList<byte[]>();
            rawFields.add(ByteArrays.toByteArray(operationCode.intValue()));
            rawFields.add(ByteArrays.toByteArray(hardwareType));
            rawFields.add(ByteArrays.toByteArray(hardwareAddressLength));
            rawFields.add(ByteArrays.toByteArray(hops.byteValue()));
            rawFields.add(ByteArrays.toByteArray(transactionIdentifier));
            rawFields.add(ByteArrays.toByteArray(seconds.intValue()));
            rawFields.add(ByteArrays.toByteArray(flags));
            rawFields.add(ByteArrays.toByteArray(ciaddr));
            rawFields.add(ByteArrays.toByteArray(yiaddr));
            rawFields.add(ByteArrays.toByteArray(siaddr));
            rawFields.add(ByteArrays.toByteArray(giaddr));
            rawFields.add(ByteArrays.toByteArray(chaddr));
            rawFields.add(ByteArrays.toByteArray(sname));
            rawFields.add(ByteArrays.toByteArray(file));
            rawFields.add(ByteArrays.toByteArray(options));
            return rawFields;
        }

        @Override
        public int length() {
            return DHCP_HEADER_SIZE;
        }

        @Override
        protected String buildString() {
            StringBuilder sb = new StringBuilder();
            String ls = System.getProperty("line.separator");

            sb.append("[DHCPv4 Header (").append(length()).append(" bytes)]").append(ls);
            sb.append("  Operation Code: ").append(operationCode).append(ls);
            sb.append("  Hardware type: ").append(hardwareType).append(ls);
            sb.append("  Hardware address length: ").append(hardwareAddressLength).append(ls);
            sb.append("  Hops: ").append(hops).append(ls);
            sb.append("  TransactionIdentifier: ").append(transactionIdentifier).append(ls);
            sb.append("  seconds: ").append(seconds).append(ls);
            sb.append("  flags: ").append(flags).append(ls);
            sb.append("  ciaddr: ").append(ciaddr).append(ls);
            sb.append("  yiaddr: ").append(yiaddr).append(ls);
            sb.append("  siaddr: ").append(siaddr).append(ls);
            sb.append("  giaddr: ").append(giaddr).append(ls);
            sb.append("  chaddr: ").append(chaddr).append(ls);
            sb.append("  sname: ").append(sname).append(ls);
            sb.append("  file: ").append(file).append(ls);
            sb.append("  options: ").append(options).append(ls);

            return sb.toString();
        }

        @Override
        public boolean equals(Object obj){
            if (obj == this) {
                return true;
            }
            if (!this.getClass().isInstance(obj)) {
                return false;
            }

            DhcpV4Packet.DhcpV4Header other = (DhcpV4Packet.DhcpV4Header) obj;
            return operationCode.equals(other.getOperationCode())
                    && hardwareType == other.hardwareType
                    && hardwareAddressLength == other.hardwareAddressLength
                    && hops.equals(other.hops)
                    && transactionIdentifier == other.transactionIdentifier
                    && seconds.equals(other.seconds)
                    && flags == (other.flags)
                    && ciaddr.equals(other.ciaddr)
                    && yiaddr.equals(other.yiaddr)
                    && siaddr.equals(other.siaddr)
                    && giaddr.equals(other.giaddr)
                    && chaddr.equals(other.chaddr)
                    && sname == (other.sname)
                    && file == (other.file)
                    && options == (other.options);
            /**
             * TODO equals function: fix types of these header values on creation
             */
        }

        @Override
        protected int calcHashCode() {
            int result = 17;
            result = 31 * result + operationCode.hashCode();
            result = 31 * result + hardwareType.hashCode();
            result = 31 * result + hardwareAddressLength;
            result = 31 * result + hops.hashCode();
            result = 31 * result + transactionIdentifier;
            result = 31 * result + seconds.hashCode();
            result = 31 * result + flags.hashCode();
            result = 31 * result + ciaddr.hashCode();
            result = 31 * result + yiaddr.hashCode();
            result = 31 * result + siaddr.hashCode();
            result = 31 * result + giaddr.hashCode();
            result = 31 * result + chaddr.hashCode();
            result = 31 * result + sname.hashCode();
            result = 31 * result + file.hashCode();
            result = 31 * result + options.hashCode();
            return result;
        }


    }

}
