package org.pcap4j.packet;

import org.pcap4j.packet.namednumber.DhcpV4HardwareType;
import org.pcap4j.packet.namednumber.DhcpV4Operation;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.DhcpV4Bytes;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import static org.pcap4j.util.ByteArrays.*;
import static org.pcap4j.util.ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES;

public class BootstrapPacket extends AbstractPacket {

  private final BootstrapHeader header;

  public static BootstrapPacket newPacket(byte[] rawData, int offset, int length)
    throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new BootstrapPacket(rawData, offset, length);
  }

  private BootstrapPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException{
    this.header = new BootstrapHeader(rawData, offset, length);
  }

  private BootstrapPacket(Builder builder){
    if (builder == null
      || builder.operationCode == null
      || builder.hardwareType == null
      || builder.ciaddr == null
      || builder.yiaddr == null
      || builder.giaddr == null
      || builder.chaddr == null
    ) {
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
        .append(" builder.vendorExtensions: ")
        .append(builder.vendorExtensions);
      throw new NullPointerException(sb.toString());
    }
    this.header = new BootstrapHeader(builder);
  }

  @Override
  public BootstrapHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  public static final class Builder extends AbstractBuilder {
    private DhcpV4Operation operationCode;
    private DhcpV4HardwareType hardwareType;
    private byte hardwareAddressLength;
    private byte hops;
    private DhcpV4Bytes transactionIdentifier;
    private short seconds;
    private short unused;
    private InetAddress ciaddr;
    private InetAddress yiaddr;
    private InetAddress siaddr;
    private InetAddress giaddr;
    private MacAddress chaddr;
    private byte[] chaddrPadding;
    private byte[] sname;
    private byte[] file;
    private byte[] vendorExtensions;

    public Builder(){
    }

    private Builder(BootstrapPacket packet){
      this.operationCode = packet.header.operationCode;
      this.hardwareType = packet.header.hardwareType;
      this.hardwareAddressLength = packet.header.hardwareAddressLength;
      this.hops = packet.header.hops;
      this.transactionIdentifier = packet.header.transactionIdentifier;
      this.seconds = packet.header.seconds;
      this.unused = packet.header.unused;
      this.ciaddr = packet.header.ciaddr;
      this.yiaddr = packet.header.yiaddr;
      this.siaddr = packet.header.siaddr;
      this.giaddr = packet.header.giaddr;
      this.chaddr = packet.header.chaddr;
      this.chaddrPadding = packet.header.chaddrPadding;
      this.sname = packet.header.sname;
      this.file = packet.header.file;
      this.vendorExtensions = packet.header.vendorExtensions;
    }

    public Builder operationCode(DhcpV4Operation operationCode) {
      this.operationCode = operationCode;
      return this;
    }

    public Builder hardwareType(DhcpV4HardwareType hardwareType) {
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

    public Builder transactionIdentifier(DhcpV4Bytes transactionIdentifier) {
      this.transactionIdentifier = transactionIdentifier;
      return this;
    }

    public Builder seconds(short seconds) {
      this.seconds = seconds;
      return this;
    }

    public Builder unused(short unused) {
      this.unused = unused;
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

    public Builder chaddrPadding(byte[] chaddrPadding) {
      this.chaddrPadding = chaddrPadding;
      return this;
    }

    public Builder sname(byte[] sname) {
      this.sname = sname;
      return this;
    }

    public Builder file(byte[] file) {
      this.file = file;
      return this;
    }

    public Builder vendorExtensions(byte[] vendorExtensions) {
      this.vendorExtensions = vendorExtensions;
      return this;
    }

    @Override
    public BootstrapPacket build() { return new BootstrapPacket(this);}
  }

  /**
   * BOOTP Header
   */
  public static final class BootstrapHeader extends AbstractHeader{

    /**
     * Structure of Bootstrap Protocol (BOOTP)
     * OPERATION CODE (1 byte)
     * HARDWARE TYPE (1 byte)
     * HARDWARE ADDRESS LENGTH (1 byte)
     * HOPS (1 byte)
     * TRANSACTION IDENTIFIER (xid) (4 bytes)
     * SECONDS (2 bytes)
     * UNUSED FIELD (2 bytes)
     * CLIENT IP address (ciaddr) (4 bytes)
     * YOUR IP address (yiaddr) (4 bytes)
     * SERVER IP address (siaddr) (4 bytes)
     * GATEWAY IP address (giaddr) (4 bytes)
     * CLIENT HARDWARE address (chaddr) (16 bytes)
     * CLIENT HARDWARE address padding (10 bytes)
     * SERVER NAME (sname) (64 bytes)
     * FILE (~Boot File Name) (128 bytes)
     * VENDOR EXTENSIONS (Vendor-specific information) (64 bytes)
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
    private static final int TRANSACTION_IDENTIFIER_SIZE = INT_SIZE_IN_BYTES;
    private static final int SECONDS_OFFSET = TRANSACTION_IDENTIFIER_OFFSET + TRANSACTION_IDENTIFIER_SIZE;
    private static final int SECONDS_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int UNUSED_OFFSET = SECONDS_OFFSET + SECONDS_SIZE;
    private static final int UNUSED_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int CIADDR_OFFSET = UNUSED_OFFSET + UNUSED_SIZE;
    private static final int CIADDR_SIZE = INET4_ADDRESS_SIZE_IN_BYTES;
    private static final int YIADDR_OFFSET = CIADDR_OFFSET + CIADDR_SIZE;
    private static final int YIADDR_SIZE = INET4_ADDRESS_SIZE_IN_BYTES;
    private static final int SIADDR_OFFSET = YIADDR_OFFSET + YIADDR_SIZE;
    private static final int SIADDR_SIZE = INET4_ADDRESS_SIZE_IN_BYTES;
    private static final int GIADDR_OFFSET = SIADDR_OFFSET + SIADDR_SIZE;
    private static final int GIADDR_SIZE = INET4_ADDRESS_SIZE_IN_BYTES;
    private static final int CHADDR_OFFSET = GIADDR_OFFSET + GIADDR_SIZE;
    private static final int CHADDR_SIZE = MacAddress.SIZE_IN_BYTES;
    private static final int CHADDRPADDING_OFFSET = CHADDR_OFFSET + CHADDR_SIZE;
    private static final int CHADDRPADDING_SIZE = 10;
    private static final int SNAME_OFFSET = CHADDRPADDING_OFFSET + CHADDRPADDING_SIZE;
    private static final int SNAME_SIZE = 64;
    private static final int FILE_OFFSET = SNAME_OFFSET + SNAME_SIZE;
    private static final int FILE_SIZE = 128;
    private static final int VENDOR_EXTENSTIONS_OFFSET = FILE_OFFSET + FILE_SIZE;
    private static final int VENDOR_EXTENSIONS_SIZE = 64;
    private static final int BOOTP_HEADER_SIZE = VENDOR_EXTENSTIONS_OFFSET + VENDOR_EXTENSIONS_SIZE;

    private final DhcpV4Operation operationCode;
    private final DhcpV4HardwareType hardwareType;
    private final byte hardwareAddressLength;
    private final byte hops;
    private final DhcpV4Bytes transactionIdentifier;
    private final short seconds;
    private final short unused;
    private final InetAddress ciaddr;
    private final InetAddress yiaddr;
    private final InetAddress siaddr;
    private final InetAddress giaddr;
    private final MacAddress chaddr;
    private final byte[] chaddrPadding;
    private final byte[] sname;
    private final byte[] file;
    private final byte[] vendorExtensions;

    private BootstrapHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException{
      if(length < BOOTP_HEADER_SIZE){
        StringBuilder sb = new StringBuilder(300);
        sb.append("The data is too short to build a DHCP header")
          .append(BOOTP_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.operationCode = DhcpV4Operation.getInstance(ByteArrays.getByte(rawData, OPERATION_CODE_OFFSET + offset));
      this.hardwareType = DhcpV4HardwareType.getInstance(ByteArrays.getByte(rawData, HARDWARE_TYPE_OFFSET + offset));
      this.hardwareAddressLength = ByteArrays.getByte(rawData, HW_ADDRESS_LENGTH_OFFSET + offset);
      this.hops = ByteArrays.getByte(rawData, HOPS_OFFSET + offset);
      this.transactionIdentifier = ByteArrays.getBytes(rawData, TRANSACTION_IDENTIFIER_OFFSET + offset);
      this.seconds = ByteArrays.getShort(rawData, SECONDS_OFFSET + offset);
      this.unused = ByteArrays.getShort(rawData, UNUSED_OFFSET + offset);
      this.ciaddr = ByteArrays.getInet4Address(rawData, CIADDR_OFFSET + offset);
      this.yiaddr = ByteArrays.getInet4Address(rawData, YIADDR_OFFSET + offset);
      this.siaddr = ByteArrays.getInet4Address(rawData, SIADDR_OFFSET + offset);
      this.giaddr = ByteArrays.getInet4Address(rawData, GIADDR_OFFSET + offset);
      this.chaddr = ByteArrays.getMacAddress(rawData, CHADDR_OFFSET + offset);
      this.chaddrPadding = ByteArrays.getSubArray(rawData, CHADDRPADDING_OFFSET + offset, CHADDRPADDING_SIZE);
      this.sname = ByteArrays.getSubArray(rawData, SNAME_OFFSET + offset, SNAME_SIZE);
      this.file = ByteArrays.getSubArray(rawData, FILE_OFFSET + offset, FILE_SIZE);
      this.vendorExtensions = ByteArrays.getSubArray(rawData, VENDOR_EXTENSTIONS_OFFSET + offset, VENDOR_EXTENSIONS_SIZE);
    }

    private BootstrapHeader(Builder builder){
      this.operationCode = builder.operationCode;
      this.hardwareType = builder.hardwareType;
      this.hardwareAddressLength = builder.hardwareAddressLength;
      this.hops = builder.hops;
      this.transactionIdentifier = builder.transactionIdentifier;
      this.seconds = builder.seconds;
      this.unused = builder.unused;
      this.ciaddr = builder.ciaddr;
      this.yiaddr = builder.yiaddr;
      this.siaddr = builder.siaddr;
      this.giaddr = builder.giaddr;
      this.chaddr = builder.chaddr;
      this.chaddrPadding = builder.chaddrPadding;
      this.sname = builder.sname;
      this.file = builder.file;
      this.vendorExtensions = builder.vendorExtensions;
    }

    public DhcpV4Operation getOperationCode() {
      return operationCode;
    }

    public DhcpV4HardwareType getHardwareType() {
      return hardwareType;
    }

    public byte getHardwareAddressLength() {
      return hardwareAddressLength;
    }

    public byte getHops() {
      return hops;
    }

    public DhcpV4Bytes getTransactionIdentifier() {
      return transactionIdentifier;
    }

    public short getSeconds() {
      return seconds;
    }

    public short getUnused() {
      return unused;
    }

    public InetAddress getCiaddr() {
      return ciaddr;
    }

    public InetAddress getYiaddr() {
      return yiaddr;
    }

    public InetAddress getSiaddr() {
      return siaddr;
    }

    public InetAddress getGiaddr() {
      return giaddr;
    }

    public MacAddress getChaddr() {
      return chaddr;
    }

    public byte[] getChaddrPadding() {
      return chaddrPadding;
    }

    public byte[] getSname() {
      return sname;
    }

    public byte[] getFile() {
      return file;
    }

    public byte[] getVendorExtensions() {
      return vendorExtensions;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<>();
      rawFields.add(ByteArrays.toByteArray(operationCode.value()));
      rawFields.add(ByteArrays.toByteArray(hardwareType.value()));
      rawFields.add(ByteArrays.toByteArray(hardwareAddressLength));
      rawFields.add(ByteArrays.toByteArray(hops));
      rawFields.add(ByteArrays.toByteArray(transactionIdentifier));
      rawFields.add(ByteArrays.toByteArray(seconds));
      rawFields.add(ByteArrays.toByteArray(unused));
      rawFields.add(ByteArrays.toByteArray(ciaddr));
      rawFields.add(ByteArrays.toByteArray(yiaddr));
      rawFields.add(ByteArrays.toByteArray(siaddr));
      rawFields.add(ByteArrays.toByteArray(giaddr));
      rawFields.add(ByteArrays.toByteArray(chaddr));
      rawFields.add((chaddrPadding));
      rawFields.add((sname));
      rawFields.add((file));
      rawFields.add((vendorExtensions));
      return rawFields;
    }

    @Override
    public int length() { return BOOTP_HEADER_SIZE; }

    @Override
    protected String buildString(){
      String xid = transactionIdentifier.toString();
      String xidString = xid.replace(":", "");

      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[Bootstrap Header (").append(BOOTP_HEADER_SIZE).append(" bytes)]").append(ls);
      sb.append("  Operation code: ").append(operationCode).append(ls);
      sb.append("  Hardware type: ").append(hardwareType).append(ls);
      sb.append("  Hardware address length: ").append(hardwareAddressLength).append(ls);
      sb.append("  Hops: ").append(hops).append(ls);
      sb.append("  Transaction ID: 0x").append(xidString).append(ls);
      sb.append("  Seconds elapsed: ").append(seconds).append(ls);
      sb.append("  Unused field: ").append(unused).append(ls);
      sb.append("  Client IP address: ").append(ciaddr).append(ls);
      sb.append("  Your IP address: ").append(yiaddr).append(ls);
      sb.append("  Server IP address: ").append(siaddr).append(ls);
      sb.append("  Gateway IP address: ").append(giaddr).append(ls);
      sb.append("  Client hardware address: ").append(chaddr).append(ls);
      sb.append("  Client hardware address padding: ").append(ByteArrays.toHexString(chaddrPadding, " ")).append(ls);
      sb.append("  Server name: ").append(ByteArrays.toHexString(sname, " ")).append(ls);
      sb.append("  BOOT file name: ").append(ByteArrays.toHexString(file, " ")).append(ls);
      sb.append("  Vendor-specific information: ").append(ByteArrays.toHexString(vendorExtensions, " ")).append(ls);
      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this){
        return true;
      }
      if (!this.getClass().isInstance(obj)){
        return false;
      }
      BootstrapHeader other = (BootstrapHeader) obj;
      return operationCode.equals(other.getOperationCode())
        && hardwareType == (other.hardwareType)
        && hardwareAddressLength == (other.hardwareAddressLength)
        && hops == (other.hops)
        && transactionIdentifier == (other.transactionIdentifier)
        && seconds == (other.seconds)
        && unused == (other.unused)
        && ciaddr.equals(other.ciaddr)
        && yiaddr.equals(other.yiaddr)
        && siaddr.equals(other.siaddr)
        && giaddr.equals(other.giaddr)
        && chaddr.equals(other.chaddr)
        && chaddrPadding == (other.chaddrPadding)
        && sname == (other.sname)
        && file == (other.file)
        && vendorExtensions == (other.vendorExtensions);
    }

    @Override
    protected int calcHashCode(){
      int result = 17;
      result = 31 * result + operationCode.hashCode();
      result = 31 * result + hardwareType.hashCode();
      result = 31 * result + hardwareAddressLength;
      result = 31 * result + hops;
      result = 31 * result + transactionIdentifier.hashCode();
      result = 31 * result + seconds;
      result = 31 * result + unused;
      result = 31 * result + ciaddr.hashCode();
      result = 31 * result + yiaddr.hashCode();
      result = 31 * result + siaddr.hashCode();
      result = 31 * result + giaddr.hashCode();
      result = 31 * result + chaddr.hashCode();
      result = 31 * result + chaddrPadding.hashCode();
      result = 31 * result + sname.hashCode();
      result = 31 * result + file.hashCode();
      result = 31 * result + vendorExtensions.hashCode();
      return result;
    }
  }
}
