package cis.tp1;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;

import aescalc.Util;


/**
 *
 * @author ismail.hassan
 */
public class FileCipherXTSAES {
    public static int SECTOR_SIZE = 512;
    
//    private String keyFilename;
    
    public void encryptFile(File keyFile, File inputFile, File outputFile) throws Exception {
        
        XTSAES xaCipher = new XTSAES();
        // set the key
        
        byte[] key = Util.hex2byte(readKey(keyFile));
        xaCipher.setKey(key);
        
        long inputLength = inputFile.length();
        long tweak = makeTweak(inputLength);
        
        int totalSector = (int)(inputLength+SECTOR_SIZE-1)/SECTOR_SIZE;
        int lastSectorSize = (int) (inputLength % SECTOR_SIZE);
        
        System.out.println("File size: "+inputLength+" bytes");
        System.out.println("Last sector size: "+lastSectorSize+" bytes");
        System.out.println("Total Sector: "+totalSector);
        
        
        if (inputLength < XTSAES.AES_BLOCK_SIZE) {
            throw new Exception("File too small (less than 16 bytes)");
        }
        
        // make it so last sector is combined with the previous block
        if (lastSectorSize < XTSAES.AES_BLOCK_SIZE) {
            lastSectorSize += SECTOR_SIZE;
            totalSector -= 1;
        }
        
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(inputFile));
        BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(outputFile));
        
        byte[] plain = new byte[SECTOR_SIZE];
        byte[] cipher;
        
        // encrypt all but last block
        for(int i = 0; i < totalSector - 1; ++i) {
//            System.out.println(i*SECTOR_SIZE);
            in.read(plain, 0, SECTOR_SIZE);
            cipher = xaCipher.encryptDataUnit(plain, tweak+i);
            out.write(cipher, 0, SECTOR_SIZE);
            out.flush();
        }
        // encrypt last block
        plain = new byte[lastSectorSize];
        in.read(plain, 0, lastSectorSize);
        cipher = xaCipher.encryptDataUnit(plain, tweak+(totalSector-1));
        out.write(cipher, 0, lastSectorSize);
        out.flush();
        in.close();
        out.close();
    }
    
    public void decryptFile(File keyFile, File inputFile, File outputFile) throws Exception {
        
        XTSAES xaCipher = new XTSAES();
        
        // set the key
        byte[] key = Util.hex2byte(readKey(keyFile));
        xaCipher.setKey(key);
        
        long inputLength = inputFile.length();
        long tweak = makeTweak(inputLength);
        
        int totalSector = (int)(inputLength+SECTOR_SIZE-1)/SECTOR_SIZE;
        int lastSectorSize = (int) (inputLength % SECTOR_SIZE);
        
        if (inputLength < XTSAES.AES_BLOCK_SIZE) {
            throw new Exception("File too small (less than 16 bytes)");
        }
        
        // make it so last sector is combined with the previous block
        if (lastSectorSize < XTSAES.AES_BLOCK_SIZE) {
            lastSectorSize += SECTOR_SIZE;
            totalSector -= 1;
        }
        
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(inputFile));
        BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(outputFile));
        
        
        byte[] cipher = new byte[SECTOR_SIZE];
        byte[] plain;
        
        // encrypt all but last block
        for(int i = 0; i < totalSector - 1; ++i) {
            in.read(cipher, 0, SECTOR_SIZE);
            plain = xaCipher.decryptDataUnit(cipher, tweak+i);
            out.write(plain, 0, SECTOR_SIZE);
            out.flush();
        }
        // encrypt last block
        cipher = new byte[lastSectorSize];
        in.read(cipher, 0, lastSectorSize);
        plain = xaCipher.decryptDataUnit(cipher, tweak+(totalSector-1));
        out.write(plain, 0, lastSectorSize);
        out.flush();
        
        in.close();
        out.close();
        
    }
    
    private String readKey(File keyFile) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(keyFile));
        String key = br.readLine();
        return key;
    }
    
    // Create tweak from the length of the file.
    // Algorithm modified from https://en.wikipedia.org/wiki/Xorshift#xorshift.2A
    private static long makeTweak(long len) {
        long t = len;
        t ^= t << 12;
        t ^= t >> 25;
        t ^= t >> 27;
        return t * 2685821657736338717L;
    }
}
