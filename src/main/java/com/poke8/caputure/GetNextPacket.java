package com.poke8.caputure;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
@SuppressWarnings("javadoc")
public class GetNextPacket {

	private static final String READ_TIMEOUT_KEY = GetNextPacket.class.getName() + ".readTimeout";
	private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

	private static final String SNAPLEN_KEY = GetNextPacket.class.getName() + ".snaplen";
	private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

	private static final String BUFFER_SIZE_KEY = GetNextPacket.class.getName() + ".bufferSize";
	private static final int BUFFER_SIZE = Integer.getInteger(BUFFER_SIZE_KEY, 1 * 1024 * 1024); // [bytes]

	private static final String TIMESTAMP_PRECISION_NANO_KEY = GetNextPacket.class.getName()
			+ ".timestampPrecision.nano";
	private static final boolean TIMESTAMP_PRECISION_NANO = Boolean.getBoolean(TIMESTAMP_PRECISION_NANO_KEY);

	private static final String NIF_NAME_KEY = GetNextPacket.class.getName() + ".nifName";
	private static final String NIF_NAME = System.getProperty(NIF_NAME_KEY);

	private GetNextPacket() {
	}

	public static void main(String[] args) throws PcapNativeException, NotOpenException, NoSuchAlgorithmException {
		if(args.length >= 2){
			SchoolAuth.setUsername(args[0]);
			SchoolAuth.setPassword(args[1]);
		}else{
			System.out.println("用户名/密码缺少");
			return;
		}
		PcapNetworkInterface nif;
		if (NIF_NAME != null) {
			nif = Pcaps.getDevByName(NIF_NAME);
		} else {
			try {
				List<PcapNetworkInterface> allDevs = null;
				try {
					allDevs = Pcaps.findAllDevs();
				} catch (PcapNativeException e) {
					throw new IOException(e.getMessage());
				}

				if (allDevs == null || allDevs.isEmpty()) {
					throw new IOException("No NIF to capture.");
				}
				int i = 0;
				for (PcapNetworkInterface dev : allDevs) {
					System.out.println(i++ + " " + dev.getDescription());
				}
				int nifIdx;
				while (true) {
					System.out.println("输入序号选择你的上网网卡或者 输入'q'退出 > ");
					BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
					String input;
					if ((input = reader.readLine()) == null) {
						continue;
					}

					if (input.equals("q")) {
						return;
					}

					try {
						nifIdx = Integer.parseInt(input);
						if (nifIdx < 0 || nifIdx >= allDevs.size()) {
							System.out.println("非法输入，请重新确认输入");
							continue;
						} else {
							break;
						}
					} catch (NumberFormatException e) {
						System.out.println("非法输入，请重新确认输入");
						continue;
					}
				}
				nif = allDevs.get(nifIdx);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}

			if (nif == null) {
				return;
			}
		}

		System.out.println(nif.getName() + " (" + nif.getDescription() + ")");
		for (PcapAddress addr : nif.getAddresses()) {
			if (addr.getAddress() != null) {
				System.out.println("IP address: " + addr.getAddress());
			}
		}
		String filter = "ether proto 0x888E and (not ether src "+nif.getLinkLayerAddresses().get(0).toString()+")";
		
		System.out.println("");
		PcapHandle.Builder phb = new PcapHandle.Builder(nif.getName()).snaplen(SNAPLEN)
				.promiscuousMode(PromiscuousMode.PROMISCUOUS).timeoutMillis(READ_TIMEOUT).bufferSize(BUFFER_SIZE);
		if (TIMESTAMP_PRECISION_NANO) {
			phb.timestampPrecision(TimestampPrecision.NANO);
		}
		PcapHandle handle = phb.build();

		handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
		int num = 0;
		//避免重复认证，与原在线冲突，有冲突时服务器会返回一个Faliure同时导致下一行start失效，需要再收到failure再次发起start
		//防挤功能
		SchoolAuth.SendLogoffPacket(nif);
		SchoolAuth.SendStartPacket(nif);
		boolean sucess = false;
		while (true) {
			Packet packet = handle.getNextPacket();
			if (packet == null) {
				continue;
			} else {
				System.out.println("收到一个"+num++);
				byte[] data = packet.getRawData();
				System.out.println(packet);
				System.out.println("--------------------");
				switch (data[18]) {
				case 1: {
					switch (data[22]) {
					case 1:
						if(sucess){
							SchoolAuth.SendResponseIdentity2(nif, data);
						}else{
							SchoolAuth.SendResponseIdentity(nif, data);
						}
						
						break;
					case 2:
						SchoolAuth.SendResponseNotification(nif, data);
						break;
					case 4:
						SchoolAuth.SendResponseMD5(nif, data);
						break;
					case 20:
						SchoolAuth.SendResponseSRP(nif, data);
						break;
					default:
						break;
					}
				}
					break;
				case 3:
					System.out.println("认证成功！");
					sucess = true;
					break;
				case 4:
					{System.out.println("认证失败!");
					sucess = false;
					SchoolAuth.SendLogoffPacket(nif);
					SchoolAuth.SendStartPacket(nif);
					break;
					}
				case 10: {};break;
				default:
					break;
				}
			}
		}
	}

}
