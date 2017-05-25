package cis.tp1;

import aescalc.AES;

/**
 *
 * @author ismail.hassan
 */

/*
Kelas ini mengimplementasi algoritma XTS-AES untuk satu data unit.
Algoritma yang digunakan diambil dari dokumen 1619-2007-NIST-_XTS-AES_Standard_.pdf.
*/


public class XTSAES {

    public static final int AES_BLOCK_SIZE = 16;
    
    private static final int GF128_POLYNOMIAL_CARRY = 135;
    
    private byte[] key1;
    private byte[] key2;
    public boolean debug;
    
    public XTSAES() {
        debug = false;
    }
    
    public void setKey(byte[] key) throws Exception {
        if (key.length%32 != 0) {
            throw new Exception("Key size too small. Have "+key.length);
        }
        this.key1 = new byte[key.length/2];
        this.key2 = new byte[key.length/2];
        System.arraycopy(key, 0, this.key1, 0, key.length/2);
        System.arraycopy(key, key.length/2, this.key2, 0, key.length/2);
    }
    
    public byte[] encryptDataUnit(byte[] plaintext, long tweak) throws Exception {
        if (plaintext.length < AES_BLOCK_SIZE) {
            throw new Exception("Plaintext size too small (less than 16 bytes)");
        }
        
        int dataSize = plaintext.length;
        int totalBlock = dataSize/AES_BLOCK_SIZE;
        
        byte[] ciphertext = new byte[dataSize];
        
        byte[][] tweakAlpha = createTweakAlphaTable(tweak, totalBlock);
        
        byte[] tmpPlainBlock = new byte[AES_BLOCK_SIZE];
        byte[] tmpCipherBlock = null;
        
        for(int i = 0; i <= totalBlock-2; ++i) {
            tmpPlainBlock = readBlock(plaintext, i);
            tmpCipherBlock = encryptBlock(tmpPlainBlock, tweakAlpha[i]);
            writeBlock(ciphertext, tmpCipherBlock, i);
        }
        
        int lastBlockSize = dataSize % AES_BLOCK_SIZE;
        if (lastBlockSize == 0) {
            tmpPlainBlock = readBlock(plaintext, totalBlock-1);
            tmpCipherBlock = encryptBlock(tmpPlainBlock, tweakAlpha[totalBlock-1]);
            
            writeBlock(ciphertext, tmpCipherBlock, totalBlock-1);
        }
        else {
            // ambil blok ke m-1, lalu enkripsi
            tmpPlainBlock = readBlock(plaintext, totalBlock-1);
            tmpCipherBlock = encryptBlock( tmpPlainBlock, tweakAlpha[totalBlock-1]);
            
            // tulis lastBlockSize pertama cipher ke blok m
            System.arraycopy(tmpCipherBlock, 0, ciphertext, (totalBlock)*AES_BLOCK_SIZE, lastBlockSize);
            
            // ambil sisa plaintext
            System.arraycopy(plaintext, (totalBlock)*AES_BLOCK_SIZE, tmpCipherBlock, 0, lastBlockSize);
            tmpCipherBlock = encryptBlock(tmpCipherBlock, tweakAlpha[totalBlock]);
            writeBlock(ciphertext, tmpCipherBlock, totalBlock-1);
        }
        return ciphertext;
    }
    
    public byte[] decryptDataUnit(byte[] ciphertext, long tweak) throws Exception {
        if (ciphertext.length < AES_BLOCK_SIZE) {
            throw new Exception("Plaintext size too small (less than 16 bytes)");
        }
        
        int dataSize = ciphertext.length;
        int totalBlock = dataSize/AES_BLOCK_SIZE;
        
        byte[] plaintext = new byte[dataSize];
        
        byte[][] tweakAlpha = createTweakAlphaTable(tweak, totalBlock);
        
        byte[] tmpCipherBlock = new byte[AES_BLOCK_SIZE];
        byte[] tmpPlainBlock;
        for(int i = 0; i <= totalBlock-2; ++i) {
            tmpCipherBlock = readBlock(ciphertext, i);
            tmpPlainBlock = decryptBlock(tmpCipherBlock, tweakAlpha[i]);
            writeBlock(plaintext, tmpPlainBlock, i);
        }
        
        int lastBlockSize = dataSize % AES_BLOCK_SIZE;
        if (lastBlockSize == 0) {
            tmpCipherBlock = readBlock(ciphertext, (totalBlock-1));
            tmpPlainBlock = decryptBlock(tmpCipherBlock, tweakAlpha[totalBlock-1]);
            writeBlock(plaintext, tmpPlainBlock, (totalBlock-1));
        }
        
        else {
            // ambil blok ke m-1
            tmpCipherBlock = readBlock(ciphertext, totalBlock-1);
            tmpPlainBlock = decryptBlock(tmpCipherBlock, tweakAlpha[totalBlock]);
            
            // tulis lastBlockSize pertama cipher ke blok m
            
            System.arraycopy(tmpPlainBlock, 0, plaintext, (totalBlock)*AES_BLOCK_SIZE, lastBlockSize);
            
            // Steal 
            System.arraycopy(ciphertext, (totalBlock)*AES_BLOCK_SIZE, tmpPlainBlock, 0, lastBlockSize);
            
            tmpPlainBlock = decryptBlock(tmpPlainBlock, tweakAlpha[totalBlock-1]);
            writeBlock(plaintext, tmpPlainBlock, totalBlock-1);
        }
        return plaintext;
    }
    
    private byte[] readBlock(byte[] dataUnit, int blockNumber) {
        byte[] blockData = new byte[AES_BLOCK_SIZE];
        System.arraycopy(dataUnit, blockNumber*AES_BLOCK_SIZE, //from
                blockData, 0, //to
                AES_BLOCK_SIZE); // length
        return blockData;
    }
    
    private void writeBlock(byte[] dataUnit, byte[] blockData, int blockNumber) {
        System.arraycopy(blockData, 0, 
                dataUnit, blockNumber*AES_BLOCK_SIZE, 
                AES_BLOCK_SIZE);
    }
    
    private byte[] encryptBlock(byte[] plainBlock, byte[] tweakAlpha) {
        AES aes1 = new AES();
        aes1.setKey(key1);
        byte[] cipherBlock = aes1.encrypt( addGF128(plainBlock, tweakAlpha) );
        
        if (debug) {
            System.out.println("Tw: " + Helper.toBits(tweakAlpha));
//            System.out.println("Pb: " + toBits(plainBlock));
            System.out.println("Cb: " + Helper.toBits(cipherBlock));
        }
        
        cipherBlock = addGF128(cipherBlock, tweakAlpha);
        
        if (debug) {
            System.out.println("Ca: " + Helper.toBits(cipherBlock));
        }
        
        
        return cipherBlock;
    }
    
    private byte[] decryptBlock(byte[] plainBlock, byte[] tweakAlpha) {
        AES aes1 = new AES();
        aes1.setKey(key1);
        byte[] cipherBlock = aes1.decrypt( addGF128(plainBlock, tweakAlpha) );
        
        cipherBlock = addGF128(cipherBlock, tweakAlpha);
        
        return cipherBlock;
    }
    
    private byte[][] createTweakAlphaTable(long tweak, int totalBlock) {
        byte[][] tweakAlpha = new byte[totalBlock+1][AES_BLOCK_SIZE];
        
        // reverse the tweak
        for(int i = 0; i < AES_BLOCK_SIZE; ++i) {
            tweakAlpha[0][i] = (byte) (tweak & 0xFF);
            tweak = tweak >> 8;
        }
        
        // encrypt the tweak
        AES aes2 = new AES();
        aes2.setKey(key2);
        
        tweakAlpha[0] = aes2.encrypt(tweakAlpha[0]);
        
        for(int i = 1; i < totalBlock+1; ++i) {
            byte carryOut = 0;
            byte carryIn = 0;
            for(int j = 0; j < AES_BLOCK_SIZE; ++j) {
                carryOut = (byte) ((tweakAlpha[i-1][j] >> 7) & 1);
                // t[j]*2 + carry[j-1]
                tweakAlpha[i][j] = (byte) (((tweakAlpha[i-1][j] << 1) ^ carryIn) & 0xFF);
                carryIn = carryOut;
            }
            if (carryOut > 0) {
                tweakAlpha[i][0] = (byte) (tweakAlpha[i][0] ^ GF128_POLYNOMIAL_CARRY);
            }
        }
        
        return tweakAlpha;
    }
    
    private byte[] addGF128(byte[] a, byte[] b) {
        byte[] res = new byte[16];
        for(int i = 0; i < 16; ++i) {
            res[i] = (byte) (a[i] ^ b[i]);
        }
        return res;
    }
}
