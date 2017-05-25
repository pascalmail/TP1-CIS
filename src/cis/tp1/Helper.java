package cis.tp1;

/**
 * 
 * @author ismail.hassan
 */
public class Helper {
    public static String bits(byte b) {
        String s = Integer.toBinaryString(Byte.toUnsignedInt(b));
        String pad = "";
        for(int i = 0; i < 8-s.length(); ++i) {
            pad += "0";
        }
        return pad+s;
    }
    
    public static String toBits(byte[] b) {
        String out = "";
        for(int i = 0; i < b.length; ++i) {
            out += bits(b[i])+ " ";
        }
        return out;
    }
}
