package com.poke8.caputure;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.sample.SendArpRequest;
import org.pcap4j.util.MacAddress;

import com.poke8.utils.ByteUtil;
public class SchoolAuth {
	private static final String READ_TIMEOUT_KEY = SendArpRequest.class.getName() + ".readTimeout";
	private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]
	private static final String SNAPLEN_KEY = SendArpRequest.class.getName() + ".snaplen";
	private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]
	private static String username = new char[16].toString();
	private static String password = new char[16].toString();
	private static String IP = new char[4].toString();
	private static byte[] fillBase64Byte = new byte[28];

	public static String getUsername() {
		return username;
	}

	public static void setUsername(String username) {
		SchoolAuth.username = username;
	}

	public static String getPassword() {
		return password;
	}

	public static void setPassword(String password) {
		SchoolAuth.password = password;
	}

	static EthernetPacket.Builder packetBuilder = new EthernetPacket.Builder();

	/* 随机数产生算法 */
	static int Random3() {
		long seed = System.currentTimeMillis();
		Random r = new Random(seed);
		return Math.abs(r.nextInt());
	}

	/* 加密算法 */
	static void XOR(byte data[], int datalen, byte key[], int keylen) {
		// 使用密钥key[]对数据data[]进行异或加密
		/* （注：该函数也可反向用于解密） */
		int i, j;

		// 先按正序处理一遍
		for (i = 0; i < datalen; i++) {
			data[i] ^= key[i % keylen];
		}
		// 再按倒序处理第二遍
		for (i = datalen - 1, j = 0; j < datalen; i--, j++) {
			data[i] ^= key[j % keylen];
		}
	}

	/* 客户端版本信息 */
	static void FillClientVersionArea(byte[] pad, int length) {
		// final String H3C_VERSION = "EN\\x11V7.00-0102"; // 华为客户端版本号(根据所需自行修改)
		byte[] nullByte = { 0x0, 0x0, 0x0 };
		final String H3C_VERSION = "EN\021V7.00-0102"; // 华为客户端版本号(根据所需自行修改)
		final String H3C_KEY = "Oly5D62FaE94W7"; // H3C的固定密钥
		int random = Random3(); // 注：可以选任意32位整数
		System.out.println(random);
		String RandomKey = String.format("%08x", random);

		// 第一轮异或运算，以RandomKey为密钥加密16字节
		byte[] area = ByteUtil.concat(H3C_VERSION.getBytes(), nullByte);
		System.out.println(new String(area));
		XOR(area, 16, RandomKey.getBytes(), RandomKey.length());
		byte[] randomByte = new byte[4];
		ByteUtil.putInt(randomByte, ByteUtil.htonl(random), 0);
		byte[] area2 = ByteUtil.concat(area, randomByte);
		XOR(area2, 20, H3C_KEY.getBytes(), H3C_KEY.length());
		System.arraycopy(area2, 0, pad, length, 20);
	}

	/* Windows版本信息 */
	static byte[] FillWindowsVersionArea() {
		final String WinVersion = "170393861"; // Windows版本请不要改变
		final String H3C_KEY = "HuaWei3COM1X"; // H3C的固定密钥
		byte[] area = WinVersion.getBytes();
		XOR(area, 20, H3C_KEY.getBytes(), H3C_KEY.length());
		return area;
	}

	/* Base64加密 */
	static void FillBase64Area(byte[] pad, int length) {
		byte[] clientVersion = new byte[20];
		/* 标准的Base64字符映射表 */
		byte[] Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".getBytes();

		// 首先生成20字节加密过的H3C版本号信息
		FillClientVersionArea(clientVersion, 0);
		// 然后按照Base64编码法将前面生成的20字节数据转换为28字节ASCII字符
		int i = 0, j = 0;
		byte c1, c2, c3;
		while (j < 24) {
			c1 = clientVersion[i++];
			c2 = clientVersion[i++];
			c3 = clientVersion[i++];
			pad[length + j++] = Table[(c1 & 0xfc) >> 2];
			pad[length + j++] = Table[((c1 & 0x03) << 4) | ((c2 & 0xf0) >> 4)];
			pad[length + j++] = Table[((c2 & 0x0f) << 2) | ((c3 & 0xc0) >> 6)];
			pad[length + j++] = Table[c3 & 0x3f];
		}
		c1 = clientVersion[i++];
		c2 = clientVersion[i++];
		pad[length + 24] = Table[(c1 & 0xfc) >> 2];
		pad[length + 25] = Table[((c1 & 0x03) << 4) | ((c2 & 0xf0) >> 4)];
		pad[length + 26] = Table[((c2 & 0x0f) << 2)];
		pad[length + 27] = '=';
	}

	/* MD5加密 */
	static void FillMD5Area(byte[] digest, byte id, String pwd, byte[] srcMD5) throws NoSuchAlgorithmException {
		// 密码长度和信息长度
		int pwdlen = pwd.length();
		int msglen = 1 + pwdlen + 16;
		// 信息缓冲区
		byte msgbuf[] = new byte[msglen]; 
		// 填充数据
		msgbuf[0] = id;
		System.arraycopy(pwd.getBytes(), 0, msgbuf, 1, pwdlen);
		System.arraycopy(srcMD5, 24, msgbuf, 1 + pwdlen, 16);

		/* 计算MD5值 */
		byte[] md5 = MessageDigest.getInstance("md5").digest(msgbuf);
		System.arraycopy(md5, 0, digest, 10, md5.length);
	}

	static void SendStartPacket(PcapNetworkInterface nif) {
		MacAddress srcAddr = (MacAddress) nif.getLinkLayerAddresses().get(0);
		byte[] pad = { 1, 1, 0, 0 };
		EthernetPacket packet = packetBuilder.srcAddr(srcAddr).dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
				.type(new EtherType((short) 0x0888E, "H3C")).pad(pad).build();
		System.out.println("发送开始数据包");
		System.out.println(packet);
		System.out.println("-------------");
		System.out.println(nif.getName() + "(" + nif.getDescription() + ")");
		PcapHandle sendHandle;
		try {
			sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
			sendHandle.sendPacket(packet);
		} catch (PcapNativeException e) {
			e.printStackTrace();
		} catch (NotOpenException e) {
			e.printStackTrace();
		}

	}

	static void SendLogoffPacket(PcapNetworkInterface nif) {
		MacAddress srcAddr = (MacAddress) nif.getLinkLayerAddresses().get(0);
		byte[] pad = { 1, 2, 0, 0 };
		EthernetPacket packet = packetBuilder.srcAddr(srcAddr).dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
				.type(new EtherType((short) 0x0888E, "H3C")).pad(pad).build();
		System.out.println("发送结束数据包");
		System.out.println(packet);
		System.out.println("-------------");
		System.out.println(nif.getName() + "(" + nif.getDescription() + ")");
		PcapHandle sendHandle;
		try {
			sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
			sendHandle.sendPacket(packet);
		} catch (PcapNativeException e) {
			e.printStackTrace();
		} catch (NotOpenException e) {
			e.printStackTrace();
		}

	}

	static void SendResponseNotification(PcapNetworkInterface nif, byte data[]) {
		byte[] srcAddrByte = new byte[6];
		byte[] dstAddrByte = new byte[6];
		System.arraycopy(data, 0, srcAddrByte, 0, 6);
		System.arraycopy(data, 6, dstAddrByte, 0, 6);
		MacAddress srcAddr = MacAddress.getByAddress(srcAddrByte);
		MacAddress dstAddr = MacAddress.getByAddress(dstAddrByte);

		byte[] pad = new byte[114];
		byte[] prePad = { 0x01, 0x00, 0x00, 0x1b, 0x02, 0x01, 0x00, 0x1b, 0x02, 0x01, 0x16 };
		System.arraycopy(prePad, 0, pad, 0, prePad.length);
		FillClientVersionArea(pad, prePad.length);
		EthernetPacket packet = packetBuilder.srcAddr(srcAddr).dstAddr(dstAddr)
				.type(new EtherType((short) 0x0888E, "H3C")).pad(pad).build();
		System.out.println("发送ResponseNotification");
		System.out.println(packet);
		System.out.println("-------------");
		System.out.println(nif.getName() + "(" + nif.getDescription() + ")");
		PcapHandle sendHandle;
		try {
			sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
			sendHandle.sendPacket(packet);
		} catch (PcapNativeException e) {
			e.printStackTrace();
		} catch (NotOpenException e) {
			e.printStackTrace();
		}

	}

	static void SendResponseIdentity(PcapNetworkInterface nif, byte data[]) {
		byte[] dstAddrByte = new byte[6];
		System.arraycopy(data, 6, dstAddrByte, 0, 6);
		 MacAddress srcAddr = (MacAddress) nif.getLinkLayerAddresses().get(0);
		MacAddress dstAddr = MacAddress.getByAddress(dstAddrByte);
		byte[] pad = new byte[54];
		byte[] prePad = { 0x01, 0x00, 0x00, 0x2f, 0x02, 0x02, 0x00, 0x2f, 0x01, 0x06, 0x07 }; // 11
		System.arraycopy(prePad, 0, pad, 0, prePad.length);
		FillBase64Area(pad, prePad.length);
		System.arraycopy(pad, 11, fillBase64Byte, 0, fillBase64Byte.length); 
		pad[39] = pad[40] = 0x20;
		System.arraycopy(username.getBytes(), 0, pad, 41, username.length());
		EthernetPacket packet = packetBuilder.srcAddr(srcAddr).dstAddr(dstAddr)
				.type(new EtherType((short) 0x0888E, "H3C")).pad(pad).build();
		System.out.println("发送ResponseIdentity");
		System.out.println(packet);
		System.out.println("-------------");
		PcapHandle sendHandle;
		try {
			sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
			sendHandle.sendPacket(packet);
		} catch (PcapNativeException e) {
			e.printStackTrace();
		} catch (NotOpenException e) {
			e.printStackTrace();
		}

	}

	 //成功后仅做广播心跳回应用户名 
	 static void SendResponseIdentity2(PcapNetworkInterface nif,byte data[]) {
	 byte[] dstAddrByte = new byte[6];
	 System.arraycopy(data, 6, dstAddrByte, 0, 6);
	 MacAddress srcAddr = (MacAddress) nif.getLinkLayerAddresses().get(0);
	 MacAddress dstAddr = MacAddress.getByAddress(dstAddrByte);
	 byte[] pad = new byte[56];
	 byte[] prePad = { 0x01, 0x00, 0x00, 0x34, 0x02, 0x01, 0x00, 0x34, 0x01,
	 0x15, 0x04,0x0a,0x00,0x6e,0x27,0x06,0x07};
	 System.arraycopy(prePad, 0, pad, 0, prePad.length);
	 System.arraycopy(fillBase64Byte, 0, pad, prePad.length, fillBase64Byte.length);
	 pad[45] = pad[46] = 0x20;
	 System.arraycopy(username.getBytes(), 0, pad, 47, username.length());
	 EthernetPacket packet = packetBuilder.srcAddr(srcAddr).dstAddr(dstAddr)
	 .type(new EtherType((short) 0x0888E, "H3C")).pad(pad).build();
	 System.out.println("发送ResponseIdentity");
	 System.out.println(packet);
	 System.out.println("-------------");
	 PcapHandle sendHandle;
	 try {
	 sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS,
	 READ_TIMEOUT);
	 sendHandle.sendPacket(packet);
	 } catch (PcapNativeException e) {
	 e.printStackTrace();
	 } catch (NotOpenException e) {
	 e.printStackTrace();
	 }
	
	 }

	static void SendResponseMD5(PcapNetworkInterface nif, byte data[]) throws NoSuchAlgorithmException {
		byte[] srcAddrByte = new byte[6];
		byte[] dstAddrByte = new byte[6];
		System.arraycopy(data, 0, srcAddrByte, 0, 6);
		System.arraycopy(data, 6, dstAddrByte, 0, 6);
		MacAddress srcAddr = MacAddress.getByAddress(srcAddrByte);
		MacAddress dstAddr = MacAddress.getByAddress(dstAddrByte);
		byte[] pad = new byte[46];
		byte[] prePad = { 0x01, 0x00, 0x00, 0x20, 0x02, 0x03, 0x00, 0x20, 0x04, 0x10 };
		System.arraycopy(prePad, 0, pad, 0, prePad.length);
		FillMD5Area(pad, data[19], password, data);
		System.arraycopy(username.getBytes(), 0, pad, 26, username.length());
		EthernetPacket packet = packetBuilder.srcAddr(srcAddr).dstAddr(dstAddr)
				.type(new EtherType((short) 0x0888E, "H3C")).pad(pad).build();
		System.out.println("发送md5数据包");
		System.out.println(packet);
		System.out.println("-------------");
		System.out.println(nif.getName() + "(" + nif.getDescription() + ")");
		PcapHandle sendHandle;
		try {
			sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
			sendHandle.sendPacket(packet);
		} catch (PcapNativeException e) {
			e.printStackTrace();
		} catch (NotOpenException e) {
			e.printStackTrace();
		}
	}

	static void SendResponseSRP(PcapNetworkInterface nif, byte data[]) {
		byte[] srcAddrByte = new byte[6];
		byte[] dstAddrByte = new byte[6];
		System.arraycopy(data, 0, srcAddrByte, 0, 6);
		System.arraycopy(data, 6, dstAddrByte, 0, 6);
		MacAddress srcAddr = MacAddress.getByAddress(srcAddrByte);
		MacAddress dstAddr = MacAddress.getByAddress(dstAddrByte);
		byte[] pad = new byte[114];
		byte[] prePad = { 0x01, 0x00, 0x00, 0x36, 0x02, data[19], 0x00, 0x36, 0x14, 0x00, 0x15, 0x04 };
		System.arraycopy(prePad, 0, pad, 0, prePad.length);
		System.arraycopy(IP.getBytes(), 0, pad, 26, 4);
		pad[30] = 0x06; // carry version
		pad[31] = 0x07;
		FillBase64Area(pad, 32);
		pad[60] = pad[61] = 0x20;
		System.arraycopy(username.getBytes(), 0, pad, 62, username.length());
		EthernetPacket packet = packetBuilder.srcAddr(srcAddr).dstAddr(dstAddr)
				.type(new EtherType((short) 0x0888E, "H3C")).pad(pad).build();
		System.out.println("发送SRP数据包");
		System.out.println(packet);
		System.out.println("-------------");
		System.out.println(nif.getName() + "(" + nif.getDescription() + ")");
		PcapHandle sendHandle;
		try {
			sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
			sendHandle.sendPacket(packet);
		} catch (PcapNativeException e) {
			e.printStackTrace();
		} catch (NotOpenException e) {
			e.printStackTrace();
		}
	}
	


}
