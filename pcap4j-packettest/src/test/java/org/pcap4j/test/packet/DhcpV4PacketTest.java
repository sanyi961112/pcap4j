package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.DhcpV4Packet;
import org.pcap4j.packet.DhcpV4Packet.DhcpV4Header;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.packet.namednumber.DhcpV4HardwareType;
import org.pcap4j.packet.namednumber.DhcpV4Operation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.DhcpV4Bytes;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.pcap4j.packet.EthernetPacket.Builder;
import java.net.InetAddress;
import java.net.UnknownHostException;

@SuppressWarnings("javadoc")
public class DhcpV4PacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(DhcpV4PacketTest.class);

  private final DhcpV4Packet packet;
  private final DhcpV4Operation operationCode;
  private final DhcpV4HardwareType hardwareType;
  private final byte hardwareAddressLength;
  private final byte hops;
  private final DhcpV4Bytes transactionIdentifier;
  private final short seconds;
  private final short flags;
  private final InetAddress ciaddr;
  private final InetAddress yiaddr;
  private final InetAddress siaddr;
  private final InetAddress giaddr;
  private final MacAddress chaddr;
  private final byte[] chaddrPadding;
  private final byte[] sname;
  private final byte[] file;
  private final DhcpV4Bytes cookie;
  private final byte[] options;

  public DhcpV4PacketTest(){
    this.operationCode = DhcpV4Operation.REQUEST;
    this.hardwareType = DhcpV4HardwareType.ETHERNET;
    this.hardwareAddressLength = (byte) ByteArrays.BYTE_SIZE_IN_BYTES;
    this.hops = (byte) ByteArrays.BYTE_SIZE_IN_BYTES;
    this.transactionIdentifier = DhcpV4Bytes.DHCP_V4_BYTES;
    this.seconds = (byte) 0;
    this.flags = (byte) 0;
    try{
      this.ciaddr = InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 1});
      this.yiaddr = InetAddress.getByAddress(new byte[] {(byte) 0, (byte) 0, (byte) 0, (byte) 0});
      this.siaddr = InetAddress.getByAddress(new byte[] {(byte) 0, (byte) 0, (byte) 0, (byte) 0});
      this.giaddr = InetAddress.getByAddress(new byte[] {(byte) 0, (byte) 0, (byte) 0, (byte) 0});
    } catch (UnknownHostException e){
      throw new AssertionError();
    }
    this.chaddr = MacAddress.getByName("fe:00:00:00:00:01");
    this.chaddrPadding = (new byte[] {(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
      (byte) 0,(byte) 0,(byte) 0,(byte) 0,(byte) 0});
    this.sname = (new byte[]{(byte) 0});
    this.file = (new byte[] {(byte) 0});
    this.cookie = DhcpV4Bytes.getByName("63:82:53:63");
    this.options = (new byte[] {(byte) 0});

    DhcpV4Packet.Builder builder = new DhcpV4Packet.Builder();
    builder.operationCode(operationCode)
      .hardwareType(hardwareType)
      .hardwareAddressLength(hardwareAddressLength)
      .hops(hops)
      .transactionIdentifier(transactionIdentifier)
      .seconds(seconds)
      .flags(flags)
      .ciaddr(ciaddr)
      .yiaddr(yiaddr)
      .siaddr(siaddr)
      .giaddr(giaddr)
      .chaddr(chaddr)
      .chaddrPadding(chaddrPadding)
      .sname(sname)
      .file(file)
      .cookie(cookie)
      .options(options);
    this.packet = builder.build();
  }

  @Override
  protected Packet getPacket() throws Exception {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    Builder eb = new Builder();
    eb.dstAddr(packet.getHeader().getChaddr())
      .srcAddr(packet.getHeader().getChaddr())
      .type(EtherType.IPV4)
      .payloadBuilder(new SimpleBuilder(packet))
      .paddingAtBuild(true);
    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info("########## " + DhcpV4Packet.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
    logger.info("########## " + DhcpV4Packet.class.getSimpleName() + " END ##########");
  }

  @Test
  public void testGetHeader() {
    DhcpV4Header h = packet.getHeader();
    assertEquals(operationCode, h.getOperationCode());
    assertEquals(hardwareType, h.getHardwareType());
    assertEquals(hardwareAddressLength, h.getHardwareAddressLength());
    assertEquals(hops, h.getHops());
    assertEquals(seconds, h.getSeconds());
    assertEquals(flags, h.getFlags());
    assertEquals(ciaddr, h.getCiaddr());
    assertEquals(yiaddr, h.getYiaddr());
    assertEquals(siaddr, h.getSiaddr());
    assertEquals(giaddr, h.getGiaddr());
    assertEquals(chaddr, h.getChaddr());
    assertEquals(chaddrPadding, h.getChaddrPadding());
    assertEquals(sname, h.getSname());
    assertEquals(file, h.getFile());
    assertEquals(cookie, h.getCookie());
    assertEquals(options, h.getOptions());

    DhcpV4Packet.Builder builder = packet.getBuilder();
    DhcpV4Packet p;

    builder.operationCode(DhcpV4Operation.REQUEST);
    p = builder.build();
    assertEquals((byte) 1, p.getHeader().getOperationCode());

    builder.operationCode(DhcpV4Operation.REPLY);
    p = builder.build();
    assertEquals((byte) 2, p.getHeader().getOperationCode());

    builder.hops((byte)0);
    builder.seconds((byte) 0);
    p = builder.build();
    assertEquals((byte) 0, p.getHeader().getHops());
    assertEquals((byte) 0, p.getHeader().getSeconds());

//    builder.hops((byte)1);
//    builder.seconds((byte) 1);
//    p = builder.build();
//    assertEquals((byte) 1, p.getHeader().getHops());
//    assertEquals((byte) 1, p.getHeader().getSeconds());
//
//    builder.hardwareAddressLength((byte) 1);
//    builder.flags((byte) 1);
//    p = builder.build();
//

  }

  @Test
  public void testNewPacket() {
    try{
      DhcpV4Packet p = DhcpV4Packet.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e){
      throw new AssertionError(e);
    }
  }

  @Test
  public void testNewPacketRandom() { RandomPacketTester.testClass(DhcpV4Packet.class, packet);}
}
