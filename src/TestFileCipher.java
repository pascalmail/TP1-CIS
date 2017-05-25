import cis.tp1.FileCipherXTSAES;
import java.io.File;

/**
 *
 * @author ismail.hassan
 */
public class TestFileCipher {
    public static void main(String[] args) throws Exception {
        String keyFilename = "key.txt";
        String inputFilename = "input.txt";
        String outputFilename = "output.txt";
        String decFilename = "decryptedOutput.txt";
        File keyFile = new File(keyFilename);
        File inputFile = new File(inputFilename);
        File outputFile = new File(outputFilename);
        
        
        FileCipherXTSAES fc = new FileCipherXTSAES();
        fc.encryptFile(keyFile, inputFile, outputFile);
        fc.decryptFile(keyFile, inputFile, outputFile);
        
    }
}
