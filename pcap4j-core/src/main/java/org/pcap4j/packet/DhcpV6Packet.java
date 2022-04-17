package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import org.pcap4j.packet.namednumber.DhcpV6MessageTypes;
import org.pcap4j.util.ByteArrays;

import java.util.ArrayList;
import java.util.List;

public class DhcpV6Packet extends AbstractPacket {

  private final DhcpV6Header header;

  public static DhcpV6Packet newPacket(byte[] rawData, int offset, int length)
    throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DhcpV6Packet(rawData, offset, length);
  }

  private DhcpV6Packet(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new DhcpV6Header(rawData, offset, length);
  }

  private DhcpV6Packet(Builder builder) {
    if (builder == null
      || builder.messageType == null
      || builder.transactionID == null
      || builder.options == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder :")
        .append(builder);
      throw new NullPointerException(sb.toString());
    }
    this.header = new DhcpV6Header(builder);
  }

  @Override
  public DhcpV6Header getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  public static final class Builder extends AbstractBuilder {
    private DhcpV6MessageTypes messageType;
    private byte[] transactionID;
    private byte[] options;

    public Builder() {
    }

    private Builder(DhcpV6Packet packet) {
      this.messageType = packet.header.messageType;
      this.transactionID = packet.header.transactionID;
      this.options = packet.header.options;
    }

    public DhcpV6Packet.Builder messageType(DhcpV6MessageTypes messageType) {
      this.messageType = messageType;
      return this;
    }

    public DhcpV6Packet.Builder transactionID(byte[] transactionID) {
      this.transactionID = transactionID;
      return this;
    }

    public DhcpV6Packet.Builder options(byte[] options) {
      this.options = options;
      return this;
    }

    @Override
    public DhcpV6Packet build() {
      return new DhcpV6Packet(this);
    }
  }

  public static final class DhcpV6Header extends AbstractHeader {

    /**
     * Structure of the DHCPv6
     * Message Type (1 byte)
     * Transaction ID (3 bytes)
     * Options (Variable Length)
     */

    private static final int MESSAGETYPE_OFFSET = 0;

    private static final int MESSAGETYPE_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int TRANSACTION_ID_OFFSET = MESSAGETYPE_OFFSET + MESSAGETYPE_SIZE;
    private static final int TRANSACTION_ID_SIZE = BYTE_SIZE_IN_BYTES * 3;
    private static final int OPTIONS_OFFSET = TRANSACTION_ID_OFFSET + TRANSACTION_ID_SIZE;
    private static final int OPTIONS_SIZE = 8;
    private static final int DHCP_MIN_HEADER_SIZE = OPTIONS_OFFSET + OPTIONS_SIZE;

    private final DhcpV6MessageTypes messageType;

    private final byte[] transactionID;

    private final byte[] options;

    private DhcpV6Header(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < DHCP_MIN_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(300);
        sb.append("The data is too short to build a DHCPv6 header")
          .append(DHCP_MIN_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.messageType = DhcpV6MessageTypes.getInstance(ByteArrays.getByte(rawData, MESSAGETYPE_OFFSET + offset));
      this.transactionID = (rawData);
      this.options = (rawData);

    }

    private DhcpV6Header(Builder builder) {
      this.messageType = builder.messageType;
      this.transactionID = builder.transactionID;
      this.options = builder.options;
    }

    public DhcpV6MessageTypes getMessageType() {
      return messageType;
    }

    public byte[] getTransactionID() {
      return transactionID;
    }

    public byte[] getOptions() {
      return options;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<>();
      rawFields.add(ByteArrays.toByteArray(messageType.value()));
//        rawFields.add(ByteArrays.toByteArray(transactionID));
//        rawFields.add(ByteArrays.toByteArray(options));
      return rawFields;
    }

    @Override
    public int length() {
      return DHCP_MIN_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[DHCPv6 Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Message type: ").append(getMessageType()).append(ls);
      sb.append("  Transaction ID: ").append(transactionID).append(ls);
      sb.append("  Options: ").append(options).append(ls);

      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) {
        return true;
      }
      if (!this.getClass().isInstance(obj)) {
        return false;
      }

      DhcpV6Packet.DhcpV6Header other = (DhcpV6Packet.DhcpV6Header) obj;
      return messageType.equals(other.getMessageType())
        && transactionID == (other.transactionID)
        && options == (other.options);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + messageType.hashCode();
      result = 31 * result + transactionID.hashCode();
      result = 31 * result + options.hashCode();
      return result;
    }

  }
}
