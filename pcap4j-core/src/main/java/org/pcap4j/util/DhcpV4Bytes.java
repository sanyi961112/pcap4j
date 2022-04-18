package org.pcap4j.util;

import java.util.regex.Matcher;

public final class DhcpV4Bytes extends LinkLayerAddress {

  public static final DhcpV4Bytes DHCP_V4_BYTES =
    DhcpV4Bytes.getByAddress(
      new byte[] {(byte) 255, (byte) 255, (byte) 255, (byte) 255});

  public static final int SIZE_IN_BYTES = 4;

  private DhcpV4Bytes(byte[] address) {
    super(address);
  }

  public static DhcpV4Bytes getByAddress(byte[] address) {
    if (address.length != SIZE_IN_BYTES) {
      throw new IllegalArgumentException(
        ByteArrays.toHexString(address, "")
          + " is invalid for address. The length must be "
          + SIZE_IN_BYTES);
    }
    return new DhcpV4Bytes(ByteArrays.clone(address));
  }

  public static DhcpV4Bytes getByName(String name) {
    Matcher m = HEX_SEPARATOR_PATTERN.matcher(name);
    m.find();
    return getByName(name, m.group(1));
  }
  
  public static DhcpV4Bytes getByName(String name, String separator) {
    return getByAddress(ByteArrays.parseByteArray(name, separator));
  }
}
