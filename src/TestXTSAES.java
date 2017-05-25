import aescalc.Util;
import cis.tp1.XTSAES;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author ismail.hassan
 */
public class TestXTSAES {
    public static void main(String[] args) throws Exception {
        String key = "0102030405060708091011121314151617181920212223242526272829303132";
        
        String data = "Kriptografi dan keamanan informasi Kriptografi dan keamanan informasi";
        byte[] rawData = data.getBytes();
        
        String data2 = "Kriptografi dan keamanan informasi Kriptografi dan keamanan informasi"
                + "Kriptografi dan keamanan informasi"
                + "Kriptografi dan keamanan informasi"
                + "Kriptografi dan keamanan informasi"
                + "Kriptografi dan keamanan informasi";
        
        byte[] rawData2 = data2.getBytes();
        byte[] rawKey = Util.hex2byte(key);
        
        XTSAES xa = new XTSAES();
        xa.setKey(rawKey);
        xa.debug = true;
        long[] tweak;
        tweak = new long[]{-6117670020208177834L};
        long start, end;
        byte[] cipher = null;
        for(int i = 0; i < tweak.length; ++i) {
            start = System.nanoTime();
            cipher = xa.encryptDataUnit(rawData, tweak[i]);
            end = System.nanoTime();
            System.out.println("T1 " + (end-start)/10000000.0+ " ms");
            
            start = System.nanoTime();
//            cipher = xa.encryptDataUnit(rawData2, tweak[i]+1);
            end = System.nanoTime();
            System.out.println("T2 " + (end-start)/10000000.0);
            
            
            byte[] rev = xa.decryptDataUnit(cipher, tweak[i]);
            
            
            System.out.println("Len : " + rawData.length);
            System.out.println("Raw : " + Util.toHEX(rawData));
            System.out.println("Enc : " + Util.toHEX(cipher));
            System.out.println("Dec : " + Util.toHEX(rev));
        }
        
//        BufferedInputStream bis = new BufferedInputStream(new FileInputStream("D:/target.txt"));
//        byte[] tmp = new byte[rawData.length];
//        bis.read(tmp);
//        System.out.println("Tmp : " + Util.toHEX(tmp));
        byte t = (byte)129;
        
        byte tt = 0;
        tt = t; 
        System.out.println("t\t"+tt+"\t"+bits(tt));
        tt = (byte)(t << 1);
        System.out.println("t<<1\t"+tt+"\t"+bits(tt));
        tt = (byte)(t * 2);
        System.out.println("t*2\t"+tt+"\t"+bits(tt));
        tt = (byte)(t / 2);
        System.out.println("t/2\t"+tt+"\t"+bits(tt));
        tt = (byte)(t >> 1);
        System.out.println("t >> 1\t"+tt+"\t"+bits(tt));
        
        tt = (byte)((t&0xFF) >> 1);
        System.out.println("(t&0xFF)>>1\t"+tt+"\t"+bits(tt));
        
        byte g = (byte)128;
        tt = (byte)(t^g);
        System.out.println("t^g\t"+tt+"\t"+bits(tt));
        
        int[] tw = new int[]{123, 321, 22234344, 323434211};
        for(int i = 0; i < tw.length; ++i) {
            System.out.println(tw[i] + " " + makeTweak(tw[i]));
        }
//        printByte(t);
//        printByte((byte)(2*t));
//        printByte();
//        printByte((byte)(t/2));
//        printByte((byte)((t&0xFF)>>1));
        
    }
    
    // xorshift* for 64bit data
    public static long makeTweak(long len) {
        long t = len;
        t ^= t << 12;
        t ^= t >> 25;
        t ^= t >> 27;
        return t * 2685821657736338717L;
    }
    
    private static String bits(byte b) {
        String s = Integer.toBinaryString(Byte.toUnsignedInt(b));
        String pad = "";
        for(int i = 0; i < 8-s.length(); ++i) {
            pad += "0";
        }
        return pad+s;
    }
}
