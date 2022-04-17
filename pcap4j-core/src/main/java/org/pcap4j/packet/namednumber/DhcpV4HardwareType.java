package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * This is the same as ARP Hardware Type, but with Byte instead of Short
 * since ARP uses 2 bytes for Hardware Type while DHCP uses 1 byte
 * */

public final class DhcpV4HardwareType extends NamedNumber<Byte, DhcpV4HardwareType> {

  /** Ethernet (10Mb): 1 */
  public static final DhcpV4HardwareType ETHERNET = new DhcpV4HardwareType((byte) 1, "Ethernet (10Mb)");

  /** Experimental Ethernet (3Mb): 2 */
  public static final DhcpV4HardwareType EXPERIMENTAL_ETHERNET =
    new DhcpV4HardwareType((byte) 2, "Experimental Ethernet (3Mb)");

  /** Amateur Radio AX.25: 3 */
  public static final DhcpV4HardwareType AMATEUR_RADIO_AX_25 =
    new DhcpV4HardwareType((byte) 3, "Amateur Radio AX.25");

  /** Proteon ProNET Token Ring: 4 */
  public static final DhcpV4HardwareType PROTEON_PRONET_TOKEN_RING =
    new DhcpV4HardwareType((byte) 4, "Proteon ProNET Token Ring");

  /** Chaos: 5 */
  public static final DhcpV4HardwareType CHAOS = new DhcpV4HardwareType((byte) 5, "Chaos");

  /** IEEE 802 Networks: 6 */
  public static final DhcpV4HardwareType IEEE_802_NETWORKS =
    new DhcpV4HardwareType((byte) 6, "IEEE 802 Networks");

  /** ARCNET: 7 */
  public static final DhcpV4HardwareType ARCNET = new DhcpV4HardwareType((byte) 7, "ARCNET");

  /** Hyperchannel: 8 */
  public static final DhcpV4HardwareType HYPERCHANNEL = new DhcpV4HardwareType((byte) 8, "Hyperchannel");

  /** Lanstar: 9 */
  public static final DhcpV4HardwareType LANSTAR = new DhcpV4HardwareType((byte) 9, "Lanstar");

  /** Autonet byte Address: 10 */
  public static final DhcpV4HardwareType AUTONET_byte_ADDRESS =
    new DhcpV4HardwareType((byte) 10, "Autonet byte Address");

  /** LocalTalk: 11 */
  public static final DhcpV4HardwareType LOCALTALK = new DhcpV4HardwareType((byte) 11, "LocalTalk");

  /** LocalNet (IBM PCNet or SYTEK LocalNET): 12 */
  public static final DhcpV4HardwareType LOCALNET =
    new DhcpV4HardwareType((byte) 12, "LocalNet (IBM PCNet or SYTEK LocalNET)");

  /** Ultra link: 13 */
  public static final DhcpV4HardwareType ULTRA_LINK = new DhcpV4HardwareType((byte) 13, "Ultra link");

  /** SMDS: 14 */
  public static final DhcpV4HardwareType SMDS = new DhcpV4HardwareType((byte) 14, "SMDS");

  /** Frame Relay: 15 */
  public static final DhcpV4HardwareType FRAME_RELAY = new DhcpV4HardwareType((byte) 15, "Frame Relay");

  /** Asynchronous Transmission Mode (ATM): 16 */
  public static final DhcpV4HardwareType ATM_16 =
    new DhcpV4HardwareType((byte) 16, "Asynchronous Transmission Mode (ATM)");

  /** HDLC: 17 */
  public static final DhcpV4HardwareType HDLC = new DhcpV4HardwareType((byte) 17, "HDLC");

  /** Fibre Channel: 18 */
  public static final DhcpV4HardwareType FIBRE_CHANNEL =
    new DhcpV4HardwareType((byte) 18, "Fibre Channel");

  /** Asynchronous Transmission Mode (ATM): 19 */
  public static final DhcpV4HardwareType ATM_19 =
    new DhcpV4HardwareType((byte) 19, "Asynchronous Transmission Mode (ATM)");

  /** Serial Line: 20 */
  public static final DhcpV4HardwareType SERIAL_LINE = new DhcpV4HardwareType((byte) 20, "Serial Line");

  /** Asynchronous Transmission Mode (ATM): 21 */
  public static final DhcpV4HardwareType ATM_21 =
    new DhcpV4HardwareType((byte) 21, "Asynchronous Transmission Mode (ATM)");

  /** MIL-STD-188-220: 22 */
  public static final DhcpV4HardwareType MIL_STD_188_220 =
    new DhcpV4HardwareType((byte) 22, "MIL-STD-188-220");

  /** Metricom: 23 */
  public static final DhcpV4HardwareType METRICOM = new DhcpV4HardwareType((byte) 23, "Metricom");

  /** IEEE 1394.1995: 24 */
  public static final DhcpV4HardwareType IEEE_1394_1995 =
    new DhcpV4HardwareType((byte) 24, "IEEE 1394.1995");

  /** MAPOS: 25 */
  public static final DhcpV4HardwareType MAPOS = new DhcpV4HardwareType((byte) 25, "MAPOS");

  /** Twinaxial: 26 */
  public static final DhcpV4HardwareType TWINAXIAL = new DhcpV4HardwareType((byte) 26, "Twinaxial");

  /** EUI-64: 27 */
  public static final DhcpV4HardwareType EUI_64 = new DhcpV4HardwareType((byte) 27, "EUI-64");

  /** HIPARP: 28 */
  public static final DhcpV4HardwareType HIPARP = new DhcpV4HardwareType((byte) 28, "HIPARP");

  /** IP and ARP over ISO 7816-3: 29 */
  public static final DhcpV4HardwareType IP_AND_ARP_OVER_ISO_7816_3 =
    new DhcpV4HardwareType((byte) 29, "IP and ARP over ISO 7816-3");

  /** ARPSec: 30 */
  public static final DhcpV4HardwareType ARPSEC = new DhcpV4HardwareType((byte) 30, "ARPSec");

  /** IPsec tunnel: 31 */
  public static final DhcpV4HardwareType IPSEC_TUNNEL =
    new DhcpV4HardwareType((byte) 31, "IPsec tunnel");

  /** InfiniBand: 32 */
  public static final DhcpV4HardwareType INFINIBAND = new DhcpV4HardwareType((byte) 32, "InfiniBand");

  /** TIA-102 Project 25 Common Air Interface (CAI): 33 */
  public static final DhcpV4HardwareType CAI =
    new DhcpV4HardwareType((byte) 33, "TIA-102 Project 25 Common Air Interface (CAI)");

  /** Wiegand Interface: 34 */
  public static final DhcpV4HardwareType WIEGAND_INTERFACE =
    new DhcpV4HardwareType((byte) 34, "Wiegand Interface");

  /** Pure IP: 35 */
  public static final DhcpV4HardwareType PURE_IP = new DhcpV4HardwareType((byte) 35, "Pure IP");

  /** HW_EXP1: 36 */
  public static final DhcpV4HardwareType HW_EXP1 = new DhcpV4HardwareType((byte) 36, "HW_EXP1");

  /** HFI: 37 */
  public static final DhcpV4HardwareType HFI = new DhcpV4HardwareType((byte) 37, "HFI");

  /** HW_EXP2: 256 */
  public static final DhcpV4HardwareType HW_EXP2 = new DhcpV4HardwareType((byte) 256, "HW_EXP2");

  private static final Map<Byte, DhcpV4HardwareType> registry =
    new HashMap<Byte, DhcpV4HardwareType>(40);

  static {
    registry.put(ETHERNET.value(), ETHERNET);
    registry.put(EXPERIMENTAL_ETHERNET.value(), EXPERIMENTAL_ETHERNET);
    registry.put(AMATEUR_RADIO_AX_25.value(), AMATEUR_RADIO_AX_25);
    registry.put(PROTEON_PRONET_TOKEN_RING.value(), PROTEON_PRONET_TOKEN_RING);
    registry.put(CHAOS.value(), CHAOS);
    registry.put(IEEE_802_NETWORKS.value(), IEEE_802_NETWORKS);
    registry.put(ARCNET.value(), ARCNET);
    registry.put(HYPERCHANNEL.value(), HYPERCHANNEL);
    registry.put(LANSTAR.value(), LANSTAR);
    registry.put(AUTONET_byte_ADDRESS.value(), AUTONET_byte_ADDRESS);
    registry.put(LOCALTALK.value(), LOCALTALK);
    registry.put(LOCALNET.value(), LOCALNET);
    registry.put(ULTRA_LINK.value(), ULTRA_LINK);
    registry.put(SMDS.value(), SMDS);
    registry.put(FRAME_RELAY.value(), FRAME_RELAY);
    registry.put(ATM_16.value(), ATM_16);
    registry.put(HDLC.value(), HDLC);
    registry.put(FIBRE_CHANNEL.value(), FIBRE_CHANNEL);
    registry.put(ATM_19.value(), ATM_19);
    registry.put(SERIAL_LINE.value(), SERIAL_LINE);
    registry.put(ATM_21.value(), ATM_21);
    registry.put(MIL_STD_188_220.value(), MIL_STD_188_220);
    registry.put(METRICOM.value(), METRICOM);
    registry.put(IEEE_1394_1995.value(), IEEE_1394_1995);
    registry.put(MAPOS.value(), MAPOS);
    registry.put(TWINAXIAL.value(), TWINAXIAL);
    registry.put(EUI_64.value(), EUI_64);
    registry.put(HIPARP.value(), HIPARP);
    registry.put(IP_AND_ARP_OVER_ISO_7816_3.value(), IP_AND_ARP_OVER_ISO_7816_3);
    registry.put(ARPSEC.value(), ARPSEC);
    registry.put(IPSEC_TUNNEL.value(), IPSEC_TUNNEL);
    registry.put(INFINIBAND.value(), INFINIBAND);
    registry.put(CAI.value(), CAI);
    registry.put(WIEGAND_INTERFACE.value(), WIEGAND_INTERFACE);
    registry.put(PURE_IP.value(), PURE_IP);
    registry.put(HW_EXP1.value(), HW_EXP1);
    registry.put(HFI.value(), HFI);
    registry.put(HW_EXP2.value(), HW_EXP2);
  }

  /**
   * @param value value
   * @param name name
   */
  public DhcpV4HardwareType(byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a DhcpV4HardwareType object.
   */
  public static DhcpV4HardwareType getInstance(byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new DhcpV4HardwareType(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a DhcpV4HardwareType object.
   */
  public static DhcpV4HardwareType register(DhcpV4HardwareType type) {
    return registry.put(type.value(), type);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFFFF);
  }

  @Override
  public int compareTo(DhcpV4HardwareType o) {
    return value().compareTo(o.value());
  }
}
