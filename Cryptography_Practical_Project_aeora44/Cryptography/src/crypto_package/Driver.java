/**
 * Name: Akshit Arora
 * Date: 06/03/2021
 * Class: TCSS 487, Spring 2021
 * 
 *  This class is the main driver of the cryptography project, responsible for generating a feature menu and implementing the features specified in the menu.
 *  Follow the notation described in the NIST Special Publication 800-185 for implementing the features.
 *  Reference: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
 *  
 *  
 * Extra Credits Implemented:
 * 1. Compute an authentication tag (MAC) of a given file under a given passphrase.

 */

package crypto_package;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

import javax.swing.JFileChooser;

public class Driver {
	
	// Global scanner for reading the inputs from console
	static Scanner in = new Scanner(System.in);

	public static void main(String[] args) {
		getSelectedResult();
	}
	
	/**
	 * Prints the menu.
	 */
	private static void getSelectedResult() {
		int choice = -1;
		System.out.println("-------------------------------------------------- CRYPTOGRAPHY PROJECT --------------------------------------------------");
		System.out.println("----------------------------------------------------- By Akshit Arora ----------------------------------------------------");
		
		while (choice != 10) {
			System.out.println("\n");
			System.out.println("**************************************************************************************************************************");
			System.out.println("Compute a plain cryptographic hash of a given file: Enter 1");
			System.out.println("Encrypt a given data file symmetrically under a given passphrase: Enter 2");
			System.out.println("Decrypt a given symmetric cryptogram under a given passphrase: Enter 3");
			System.out.println("Generate an elliptic key pair from a given passphrase and write the public key to a file: Enter 4");
			System.out.println("Encrypt a data file under a given elliptic public key file: Enter 5");
			System.out.println("Decrypt a given elliptic-encrypted file from a given password: Enter 6");
			System.out.println("Sign a given file from a given password and write the signature to a file: Enter 7");
			System.out.println("Verify a given data file and its signature file under a given public key file: Enter 8");
			System.out.println("Extra Credit #2,  Compute an authentication tag (MAC) of a given file under a given passphrase: Press 9");
			System.out.println("Quit the App: Enter 10");
			System.out.println("**************************************************************************************************************************");
			choice = in.nextInt();
			System.out.println("Your chose: " + choice);
			if (choice < 0 || choice > 10) {
				System.out.println("Wrong Choice, Please try again!");
			}
			if (choice == 10) {
				System.out.println("\n\nTHANK YOU FOR TRYING THE APP!");
				break;
			}
			System.out.println("\n");
			displayChoice(choice);
		}
	}
	
	/**
	 * Displays the selected choice menu.
	 * @param choice, the app feature selected.
	 */
	private static void displayChoice(int choice) {
		if (choice == 1) {
			System.out.println("**************************************************************************************************************************");
			System.out.println("--------------------------------#1: Compute a plain cryptographic hash of a given file------------------------------------");
			calculatePainHash();			
		} else if (choice == 2) {
			System.out.println("**************************************************************************************************************************");
			System.out.println("------------------------#2: Encrypt a given data file symmetrically under a given passphrase------------------------------");
			encryptSymmetric();			
		} else if (choice == 3) {
			System.out.println("**************************************************************************************************************************");
			System.out.println("-------------------------3: Decrypt a given symmetric cryptogram under a given passphrase---------------------------------");
			decryptSymmetric();
		} else if (choice == 4) {
			System.out.println("**************************************************************************************************************************");
			System.out.println("----------------#4: Generate an elliptic key pair from a given passphrase and write the public key to a file--------------");
			generateEKey();
		} else if (choice == 5) {
			System.out.println("**************************************************************************************************************************");
			System.out.println("----------------------------#5: Encrypt a data file under a given elliptic public key file--------------------------------");
			encryptUsingPublicKey();
		} else if (choice == 6) {
			System.out.println("**************************************************************************************************************************");
			System.out.println("------------------------#6: Decrypt a given elliptic-encrypted file from a given password---------------------------------");
			decryptElliptic();
		} else if (choice == 7) {
			System.out.println("**************************************************************************************************************************");
			System.out.println("--------------------#7: Sign a given file from a given password and write the signature to a file--------------------------");
			signFile();
		} else if (choice == 8) {
			System.out.println("**************************************************************************************************************************");
			System.out.println("---------------------#8: Verify a given data file and its signature file under a given public key file--------------------");
			verifySig();
		} else if (choice == 9) {
			System.out.println("**************************************************************************************************************************");
			System.out.println("--------------------#9:  Compute an authentication tag (MAC) of a given file under a given passphrase.--------------------");
			computeMac();
		}
	}
	
	/**
	 * Feature #9 (Bonus/Extra Credit)
	 *  Computes an authentication tag (MAC) of a given file under a given passphrase.
	 */
	private static void computeMac() {
		// TODO Auto-generated method stub
		System.out.println("Please select the input file");
		byte[] input = getFile();
		System.out.println("Please enter the passphrase for calculating the MAC");
		byte[] pwd = in.next().getBytes();
		
		byte[] t = KMACXOF256.KMACXOF256_CALCULATOR(pwd, input, 512, "T".getBytes());
		String response = saveBytesToFile(t, true);
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
		if(response.equals("")) {
			System.out.println("Cannot save the Authentication tag (MAC) to the file");
		} else {
			System.out.println("Authentication tag (MAC) saved successfully at: " + response);
		}
	}

	/**
	 * Feature #8
	 * Verifies a signature (h, z) for a byte array m under the (Schnorr/ ECDHIES) public key V
	 */
	private static void verifySig() {
		// TODO Auto-generated method stub
		System.out.println("Please select the input file");
		byte[] input = getFile();
		System.out.println("Please select the file containing the public key");
		String[] publicKeyString = getFileLineByLine();
		System.out.println("Please select the file containing the signature");
		String[] signatureString = getFileLineByLine();
		
		//U = z*G + h*V
		EllipticCurve521 V = new EllipticCurve521(new BigInteger(hexStringToByteArray(publicKeyString[0])), new BigInteger(hexStringToByteArray(publicKeyString[1])));
	    EllipticCurve521 G = new EllipticCurve521(new BigInteger("4"));
		EllipticCurve521 U = G.multiplyScalor(new BigInteger(hexStringToByteArray(signatureString[1]))).add(V.multiplyScalor(new BigInteger(hexStringToByteArray(signatureString[0]))));
		
		byte[] h_bar = KMACXOF256.KMACXOF256_CALCULATOR(U.getX().toByteArray(), input, 512, "T".getBytes());
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
		// accept if, and only if, KMACXOF256(Ux, m, 512, “T”) = h
		if(Arrays.equals(hexStringToByteArray(signatureString[0]), h_bar)) {
			System.out.println("                                                   Signature verified successfully!");
		} else {
			System.out.println("                                                   Signature not verified!");
		}
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
	}

	/**
	 * Feature #7
	 * Generates a signature for a byte array m under the passphrase pw.
	 */
	private static void signFile() {
		// TODO Auto-generated method stub
		System.out.println("Please select the file you want to sign");
		byte[] input = getFile();
		System.out.println("Please enter the passphrase for generating the signature");
		byte[] pwd = in.next().getBytes();
		
		// s = KMACXOF256(pw, “”, 512, “K”); s = 4s
		byte[] s_bytes = KMACXOF256.KMACXOF256_CALCULATOR(pwd, "".getBytes(), 512, "K".getBytes());
		
		byte[] temp = new byte[1];
		temp[0] = (byte) 0x00;
		
		byte[] s_bytes_pos = InternalFunctions.concat_bytes(temp, s_bytes);
		BigInteger s = new BigInteger(s_bytes_pos);
		s = s.multiply(new BigInteger("4"));
		
		// k = KMACXOF256(s, m, 512, “N”); k = 4k
		byte[] k_bytes = KMACXOF256.KMACXOF256_CALCULATOR(s.toByteArray(), input, 512, "N".getBytes());
		byte[] k_bytes_pos = InternalFunctions.concat_bytes(temp, k_bytes);
		BigInteger k = new BigInteger(k_bytes_pos);
		k = k.multiply(new BigInteger("4"));
		
		// U = k*G;
	    EllipticCurve521 G = new EllipticCurve521(new BigInteger("4"));
		EllipticCurve521 U = G.multiplyScalor(k);
		
		// h = KMACXOF256(Ux, m, 512, “T”); z = (k – hs) mod r
		byte[] h_bytes = KMACXOF256.KMACXOF256_CALCULATOR(U.getX().toByteArray(), input, 512, "T".getBytes());
		byte[] h_bytes_pos = InternalFunctions.concat_bytes(temp, h_bytes);
		BigInteger h = new BigInteger(h_bytes_pos);
		BigInteger z = k.subtract(h.multiply(s)).mod(EllipticCurve521.r);
		
		String response = saveBytesToFile(h.toByteArray(), true);
		appendBytesToFile(z.toByteArray(), response);

		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
		System.out.println("Signature saved at:  " + response);
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
	}

	/**
	 * Feature #6
	 * Decrypts a cryptogram (Z, c, t) under passphrase pw
	 */
	private static void decryptElliptic() {
		// TODO Auto-generated method stub
		System.out.println("Select the file encrypted using the public key");
		String[] input = getFileLineByLine();
		System.out.println("Please enter the passphrase used while encrypting the file");
		byte[] pwd = in.next().getBytes();
		
		// s = KMACXOF256(pw, “”, 512, “K”); s = 4s
		byte[] s_bytes = KMACXOF256.KMACXOF256_CALCULATOR(pwd, "".getBytes(), 512, "K".getBytes());
		// make sure s is +ve
		byte[] temp = new byte[1];
		temp[0] = (byte) 0x00;
		byte[] s_bytes_pos = InternalFunctions.concat_bytes(temp, s_bytes);
		BigInteger s = new BigInteger(s_bytes_pos);
		s = s.multiply(new BigInteger("4"));
		
		// W = s*Z
		EllipticCurve521 Z = new EllipticCurve521(new BigInteger(hexStringToByteArray(input[0])), new BigInteger(hexStringToByteArray(input[1])));
		EllipticCurve521 W = Z.multiplyScalor(s);
		
		// (ke || ka) = KMACXOF256(Wx, “”, 1024, “P”)
		byte[] ke_and_ka = KMACXOF256.KMACXOF256_CALCULATOR(W.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
		byte[] ke = Arrays.copyOfRange(ke_and_ka, 0, 64);
		byte[] ka = Arrays.copyOfRange(ke_and_ka, 64, ke_and_ka.length);
		
		// m = KMACXOF256(ke, “”, |c|, “PKE”) xor c
		byte[] c = hexStringToByteArray(input[2]);
		byte[] m = KMACXOF256.KMACXOF256_CALCULATOR(ke, "".getBytes(), c.length * 8, "PKE".getBytes());
		for (int i = 0; i < m.length; i++) {
			m[i] = (byte) (m[i] ^ c[i]);
		}
		// t’ = KMACXOF256(ka, m, 512, “PKA”)
		byte[] t_bar = KMACXOF256.KMACXOF256_CALCULATOR(ka, m, 512, "PKA".getBytes());
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
		if(Arrays.equals(hexStringToByteArray(input[3]), t_bar)) {
			System.out.println("Decrypted Text:");
			System.out.println(new String(m));
			String response = saveBytesToFile(m, false);
			System.out.println("Text Decrypted Successfully at: " + response);
		} else {
			System.out.println("Error decrypting the text");
		}
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
	}

	/**
	 * Feature #5
	 * Encrypts a byte array m under the (Schnorr/ECDHIES) public key V
	 */
	private static void encryptUsingPublicKey() {
		// TODO Auto-generated method stub
		System.out.println("Please select the file you want to encrypt");
		byte[] input = getFile();
		System.out.println("Please select the file containing the public key");
		String[] publicKeyString = getFileLineByLine();
		
		// k = Random(512); k = 4k
		byte[] k_bytes = new byte[64];
		Random rand = new Random();
		rand.nextBytes(k_bytes);
		byte[] temp = new byte[1];
		temp[0] = (byte) 0x00;
		k_bytes = InternalFunctions.concat_bytes(temp, k_bytes); 
		BigInteger k = new BigInteger(k_bytes);
		k = k.multiply(new BigInteger("4"));
		
		// W = k*V; Z = k*G
	    EllipticCurve521 G = new EllipticCurve521(new BigInteger("4"));
		EllipticCurve521 V = new EllipticCurve521(new BigInteger(hexStringToByteArray(publicKeyString[0])), new BigInteger(hexStringToByteArray(publicKeyString[1])));
		EllipticCurve521 W = V.multiplyScalor(k);
		EllipticCurve521 Z = G.multiplyScalor(k);
		
		// (ke || ka) = KMACXOF256(Wx, “”, 1024, “P”)
		byte[] ke_and_ka = KMACXOF256.KMACXOF256_CALCULATOR(W.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
		byte[] ke = Arrays.copyOfRange(ke_and_ka, 0, 64);
		byte[] ka = Arrays.copyOfRange(ke_and_ka, 64, ke_and_ka.length);

		// c = KMACXOF256(ke, “”, |m|, “PKE”) xor m
		byte[] c = KMACXOF256.KMACXOF256_CALCULATOR(ke, "".getBytes(), input.length * 8, "PKE".getBytes());
		for (int i = 0; i < c.length; i++) {
			c[i] = (byte) (c[i] ^ input[i]);
		}
		
		// t = KMACXOF256(ka, m, 512, “SKA”)
		byte[] t = KMACXOF256.KMACXOF256_CALCULATOR(ka, input, 512, "PKA".getBytes());
		
		String response = saveBytesToFile(Z.getX().toByteArray(), true);
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
		if(response.equals("")) {
			System.out.println("Cannot save the cryptogram to file");
		} else {
			System.out.println("File encrypted successfully at location: " + response);
		}
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
		appendBytesToFile(Z.getY().toByteArray(), response);	
		appendBytesToFile(c, response);
		appendBytesToFile(t, response);
	}

	/**
	 * Feature #4
	 * Generates a (Schnorr/ECDHIES) key pair from passphrase pw
	 */
	private static void generateEKey() {
		System.out.println("Please enter the passphase you want to use for generating the public key");
		String pwd = in.next();
		// s = KMACXOF256(pw, “”, 512, “K”); s = 4s
		byte[] s_bytes = KMACXOF256.KMACXOF256_CALCULATOR(pwd.getBytes(), "".getBytes(), 512, "K".getBytes());
		byte[] temp = new byte[1];
		// making sure the bytes are positive
		temp[0] = (byte) 0x00;
		byte[] s_bytes_pos = InternalFunctions.concat_bytes(temp, s_bytes);
		BigInteger s = new BigInteger(s_bytes_pos);
		s = s.multiply(new BigInteger("4"));
		// V = s*G
	    EllipticCurve521 G = new EllipticCurve521(new BigInteger("4"));
		EllipticCurve521 V = G.multiplyScalor(s);
		// key pair: (s, V)
		byte[] x = V.getX().toByteArray();
		byte[] y = V.getY().toByteArray();
		String path = saveBytesToFile(x, true);
		appendBytesToFile(y, path);
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
		if (!path.equals("")) {
			System.out.println("Public key generated successfully at: " + path);
		} else {
			System.out.println("Not able to save the generated public key. Please try again!");
		}
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
	}

	/**
	 * Feature #3
	 * Decrypts a symmetric cryptogram (z, c, t) under passphrase pw
	 */
	private static void decryptSymmetric() {
		System.out.println("Please select the file encrypted using symmetric encryption");
		String[] input = getFileLineByLine();
		System.out.println("Please enter the passphrase used to encrypt the file");
		byte[] pwd = in.next().getBytes();
		byte[] z = hexStringToByteArray(input[0]);
		byte[] c = hexStringToByteArray(input[1]);
		byte[] t = hexStringToByteArray(input[2]);

		// (ke || ka) = KMACXOF256(z || pw, “”, 1024, “S”)
		byte[] ke_and_ka = KMACXOF256.KMACXOF256_CALCULATOR(InternalFunctions.concat_bytes(z, pwd), "".getBytes(), 1024, "S".getBytes());
		byte[] ke = Arrays.copyOfRange(ke_and_ka, 0, 64);
		byte[] ka = Arrays.copyOfRange(ke_and_ka, 64, ke_and_ka.length);
		
		// m = KMACXOF256(ke, “”, |c|, “SKE”) xor c
		byte[] m = KMACXOF256.KMACXOF256_CALCULATOR(ke, "".getBytes(), c.length * 8, "SKE".getBytes());
		for (int i = 0; i < m.length; i++) {
			m[i] = (byte) (m[i] ^ c[i]);
		}
		
		// t’ = KMACXOF256(ka, m, 512, “SKA”)
		byte[] t_bar = KMACXOF256.KMACXOF256_CALCULATOR(ka, m, 512, "SKA".getBytes()); 
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
		
		// accept if, and only if, t’ = t
		if(Arrays.equals(t, t_bar)) {
			System.out.println("Decrypted Text:");
			System.out.println(new String(m));
			String response = saveBytesToFile(m, false);
			System.out.println("Text Decrypted Successfully at: " + response);
		} else {
			System.out.println("Error decrypting the text");
		}
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
	}
	
	/**
	 * Feature #2
	 * Encrypts a byte array m symmetrically under passphrase pw
	 * Reference: Generate 512 random bits: https://www.tutorialspoint.com/java/util/random_nextbytes.htm
	 */
	private static void encryptSymmetric() {
		System.out.println("Please select the input file.");
		byte[] inputMessage = getFile();
		System.out.println("Please enter the passphrase");
		byte[] pwd = in.next().getBytes();
		
		// z = Random(512)
		byte[] z = new byte[64];
		Random randomNo = new Random();
		randomNo.nextBytes(z);
		
		// (ke || ka) = KMACXOF256(z || pw, “”, 1024, “S”)
		byte[] z_and_pwd = InternalFunctions.concat_bytes(z, pwd);
		byte[] ke_and_ka = KMACXOF256.KMACXOF256_CALCULATOR(z_and_pwd, new byte[0], 1024, "S".getBytes());
		byte[] ke = Arrays.copyOfRange(ke_and_ka, 0, 64);
		byte[] ka = Arrays.copyOfRange(ke_and_ka, 64, ke_and_ka.length);
		
		// c = KMACXOF256(ke, “”, |m|, “SKE”) xor m
		byte[] c = KMACXOF256.KMACXOF256_CALCULATOR(ke, "".getBytes(), inputMessage.length * 8, "SKE".getBytes());
		for (int i = 0; i < c.length; i++) {
			c[i] = (byte) (c[i] ^ inputMessage[i]);
		}
		
		// t = KMACXOF256(ka, m, 512, “SKA”)
		byte[] t = KMACXOF256.KMACXOF256_CALCULATOR(ka, inputMessage, 512, "SKA".getBytes());
		
		// symmetric cryptogram: (z, c, t)
		String response = saveBytesToFile(z, true);
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
		if(response.equals("")) {
			System.out.println("Cannot save the symmetric cryptogram to file");
		} else {
			System.out.println("Symmetric cryptogram saved successfully at: " + response);
		}
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
		appendBytesToFile(c, response);
		appendBytesToFile(t, response);
	}

	/**
	 * Feature #1
	 * Computes a cryptographic hash h of a byte array m
	 */
	private static void calculatePainHash() {
		System.out.println("Please select the input file.");
		byte[] inputBytes = getFile();
		if (inputBytes == null) {
			System.out.println("Cannot read the file. Please try again");
		}
		// h = KMACXOF256(“”, m, 512, “D”)
		byte[] result = KMACXOF256.KMACXOF256_CALCULATOR("".getBytes(), inputBytes, 512, "D".getBytes());
		String response = saveBytesToFile(result, true);
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
		if (response.equals("")) {
			System.out.println("Error saving the cryptographic hash to the file");
		} else
			System.out.println("Cryptographic Hash Saved at: " + response);
		System.out.println("-------------------------------------------------------------------------------------------------------------------------------------");
	}

	
	/**
	 * Converts the hex string into the byte array
	 * Note: s must be an even-length string
	 * Reference, method taken from: https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
	 * @param s, the hex string
	 * @return byte array
	 */
	private static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}


	/**
	 * Generates a String array of the file read line by line
	 * @return, a string array containing the content of the file read line-by-line
	 */
	private static String[] getFileLineByLine() {
		JFileChooser j = new JFileChooser();
		j.showOpenDialog(null);
		File f = j.getSelectedFile();
		try {
			FileInputStream inStream = new FileInputStream(f);
			Scanner lineByLine = new Scanner(inStream);
			String[] lines = new String[4]; // maximum lines required for reading the files
			int i = 0;
			while(lineByLine.hasNextLine()) {
				lines[i++] = lineByLine.next();
			}
			inStream.close();
			lineByLine.close();
			return lines;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Appends the input to the passed file.
	 * @param input, the byte array of the input to be appended
	 * @param response, the location of the file that needs to be appended.
	 */
	private static void appendBytesToFile(byte[] input, String response) {
		File file = new File(response);
		try {
			FileOutputStream out = new FileOutputStream(file, true);
			out.write(System.getProperty("line.separator").getBytes());
			for (byte b: input) {
				String hex = String.format("%02X", b);
				out.write(hex.getBytes());
			}
			out.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}		
	}

	/**
	 * Gets the content of the file as a byte array
	 * @return, a byte array representing the content of the file read.
	 */
	private static byte[] getFile() {
		JFileChooser j = new JFileChooser();
		j.showOpenDialog(null);
		File f = j.getSelectedFile();
		try {
			FileInputStream inStream = new FileInputStream(f);
			byte[] result = inStream.readAllBytes();
			inStream.close();
			return result;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	
	/**
	 * Saves the generated text/byte array to the output file
	 * @param result, the byte array to be saved
	 * @return the location of the file generated.
	 */
	private static String saveBytesToFile(byte[] result, boolean isHex) {
		System.out.println("Please select the output file");
		JFileChooser j = new JFileChooser();
		j.showSaveDialog(null);
		File f = j.getSelectedFile();
		try {
			f.createNewFile();
			try {
				FileOutputStream out = new FileOutputStream(f);
				if (isHex) {
					for (byte b: result) {
						String hex = String.format("%02X", b);
						out.write(hex.getBytes());
					}
				} else {
					out.write(result);
				}
				out.close();
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return "";
			}
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return "";
		}
		return f.getAbsolutePath();
	}
}