package com.poke8.utils;

import java.util.Arrays;

public class ByteUtil {
	/**
	 * 转换short为byte
	 * 
	 * @param b
	 * @param s
	 *            需要转换的short
	 * @param index
	 */
	public static void putShort(byte b[], short s, int index) {
		b[index + 1] = (byte) (s >> 8);
		b[index + 0] = (byte) (s >> 0);
	}

	/**
	 * 通过byte数组取到short
	 * 
	 * @param b
	 * @param index
	 *            第几位开始取
	 * @return
	 */
	public static short getShort(byte[] b, int index) {
		return (short) (((b[index + 1] << 8) | b[index + 0] & 0xff));
	}

	/**
	 * 转换int为byte数组
	 * 
	 * @param bb
	 * @param x
	 * @param index
	 */
	public static void putInt(byte[] bb, int x, int index) {
		bb[index + 3] = (byte) (x >> 24);
		bb[index + 2] = (byte) (x >> 16);
		bb[index + 1] = (byte) (x >> 8);
		bb[index + 0] = (byte) (x >> 0);
	}

	/**
	 * 通过byte数组取到int
	 * 
	 * @param bb
	 * @param index
	 *            第几位开始
	 * @return
	 */
	public static int getInt(byte[] bb, int index) {
		return (int) ((((bb[index + 3] & 0xff) << 24) | ((bb[index + 2] & 0xff) << 16) | ((bb[index + 1] & 0xff) << 8)
				| ((bb[index + 0] & 0xff) << 0)));
	}

	/**
	 * 转换long型为byte数组
	 * 
	 * @param bb
	 * @param x
	 * @param index
	 */
	public static void putLong(byte[] bb, long x, int index) {
		bb[index + 7] = (byte) (x >> 56);
		bb[index + 6] = (byte) (x >> 48);
		bb[index + 5] = (byte) (x >> 40);
		bb[index + 4] = (byte) (x >> 32);
		bb[index + 3] = (byte) (x >> 24);
		bb[index + 2] = (byte) (x >> 16);
		bb[index + 1] = (byte) (x >> 8);
		bb[index + 0] = (byte) (x >> 0);
	}

	/**
	 * 通过byte数组取到long
	 * 
	 * @param bb
	 * @param index
	 * @return
	 */
	public static long getLong(byte[] bb, int index) {
		return ((((long) bb[index + 7] & 0xff) << 56) | (((long) bb[index + 6] & 0xff) << 48)
				| (((long) bb[index + 5] & 0xff) << 40) | (((long) bb[index + 4] & 0xff) << 32)
				| (((long) bb[index + 3] & 0xff) << 24) | (((long) bb[index + 2] & 0xff) << 16)
				| (((long) bb[index + 1] & 0xff) << 8) | (((long) bb[index + 0] & 0xff) << 0));
	}

	/**
	 * 字符到字节转换
	 * 
	 * @param ch
	 * @return
	 */
	public static void putChar(byte[] bb, char ch, int index) {
		int temp = (int) ch;
		// byte[] b = new byte[2];
		for (int i = 0; i < 2; i++) {
			bb[index + i] = new Integer(temp & 0xff).byteValue(); // 将最高位保存在最低位
			temp = temp >> 8; // 向右移8位
		}
	}

	/**
	 * 字节到字符转换
	 * 
	 * @param b
	 * @return
	 */
	public static char getChar(byte[] b, int index) {
		int s = 0;
		if (b[index + 1] > 0)
			s += b[index + 1];
		else
			s += 256 + b[index + 0];
		s *= 256;
		if (b[index + 0] > 0)
			s += b[index + 1];
		else
			s += 256 + b[index + 0];
		char ch = (char) s;
		return ch;
	}

	/**
	 * float转换byte
	 * 
	 * @param bb
	 * @param x
	 * @param index
	 */
	public static void putFloat(byte[] bb, float x, int index) {
		// byte[] b = new byte[4];
		int l = Float.floatToIntBits(x);
		for (int i = 0; i < 4; i++) {
			bb[index + i] = new Integer(l).byteValue();
			l = l >> 8;
		}
	}

	/**
	 * 通过byte数组取得float
	 * 
	 * @param bb
	 * @param index
	 * @return
	 */
	public static float getFloat(byte[] b, int index) {
		int l;
		l = b[index + 0];
		l &= 0xff;
		l |= ((long) b[index + 1] << 8);
		l &= 0xffff;
		l |= ((long) b[index + 2] << 16);
		l &= 0xffffff;
		l |= ((long) b[index + 3] << 24);
		return Float.intBitsToFloat(l);
	}

	/**
	 * double转换byte
	 * 
	 * @param bb
	 * @param x
	 * @param index
	 */
	public static void putDouble(byte[] bb, double x, int index) {
		// byte[] b = new byte[8];
		long l = Double.doubleToLongBits(x);
		for (int i = 0; i < 8; i++) {
			bb[index + i] = new Long(l).byteValue();
			l = l >> 8;
		}
	}

	/**
	 * 通过byte数组取得double
	 * 
	 * @param bb
	 * @param index
	 * @return
	 */
	public static double getDouble(byte[] b, int index) {
		long l;
		l = b[0];
		l &= 0xff;
		l |= ((long) b[1] << 8);
		l &= 0xffff;
		l |= ((long) b[2] << 16);
		l &= 0xffffff;
		l |= ((long) b[3] << 24);
		l &= 0xffffffffl;
		l |= ((long) b[4] << 32);
		l &= 0xffffffffffl;
		l |= ((long) b[5] << 40);
		l &= 0xffffffffffffl;
		l |= ((long) b[6] << 48);
		l &= 0xffffffffffffffl;
		l |= ((long) b[7] << 56);
		return Double.longBitsToDouble(l);
	}

	public static void putHexString(byte[] bb, String s, int index) {
		for (int i = 0; i < s.length(); i += 2) {
			byte c = (byte) (charToByte(s.charAt(i)) << 4 | charToByte(s.charAt(i + 1)));
			bb[index + (i >> 1)] = c;
		}
	}

	private static byte charToByte(char c) {
		return (byte) "0123456789ABCDEF".indexOf(c);
	}

	public static String getHexString(byte[] b, int index, int count) {
		StringBuilder stringBuilder = new StringBuilder("");
		if (b == null || index < 0 || b.length < index + count) {
			return null;
		}
		for (int i = index; i < count + index; i++) {
			int v = b[i] & 0xFF;
			String hv = Integer.toHexString(v);
			if (hv.length() < 2) {
				stringBuilder.append(0);
			}
			stringBuilder.append(hv);
		}
		return stringBuilder.toString();
	}

	public static String getBinaryString(int d, int length) {
		StringBuilder stringBuilder = new StringBuilder("");
		String hv = Integer.toBinaryString(d);
		for (int j = 0; j < length - hv.length(); j++) {
			stringBuilder.append(0);
		}
		stringBuilder.append(hv);
		return stringBuilder.toString();
	}

	public static String getBinaryReverseString(int d, int length) {
		StringBuilder stringBuilder = new StringBuilder("");
		String hv = Integer.toBinaryString(d);
		for (int j = 0; j < length - hv.length(); j++) {
			stringBuilder.append(0);
		}
		stringBuilder.append(hv);
		stringBuilder.reverse();

		return stringBuilder.toString();
	}

	// 网络字节逆序
	public static byte[] ReversEndian(byte b[], int count, boolean big) {
		byte by;
		byte data[] = new byte[count];
		for (int i = 0; i < count; i++) {
			data[i] = b[i];
		}
		if (big == false) {
			for (int i = 0; i < count; i++) {
				by = b[i];
				data[count - i - 1] = by;
			}
		}
		return data;
	}

	public static short htons(short s) {
		short rslt = 0;
		byte[] bs1 = new byte[2];
		ByteUtil.putShort(bs1, s, 0);
		byte[] bs2 = ReversEndian(bs1, 2, false);
		rslt = ByteUtil.getShort(bs2, 0);
		return rslt;
	}

	public static int htonl(int d) {
		int rslt = 0;
		byte[] bs1 = new byte[4];
		ByteUtil.putInt(bs1, d, 0);
		byte[] bs2 = ReversEndian(bs1, 4, false);
		rslt = ByteUtil.getInt(bs2, 0);
		return rslt;
	}

	public static byte[] concat(byte[] area, byte[] randomByte) {

		byte[] c = new byte[area.length + randomByte.length];

		System.arraycopy(area, 0, c, 0, area.length);

		System.arraycopy(randomByte, 0, c, area.length, randomByte.length);

		return c;

	}

}