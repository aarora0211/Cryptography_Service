/**
 * Name: Akshit Arora
 * Date: 06/03/2021
 * Class: TCSS 487, Spring 2021
 * 
 * Java Implementation of Internal functions described in Section 2.3 of NIST Special Publication 800-18.
 *  
 *  References:
 *  NIST Special Publication 800-185: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
 *  Stackoverflow
 *  
 */


package crypto_package;

import java.util.Arrays;

public class InternalFunctions {
	
	/**
	 * Encodes the integer x as a byte string in a way that can be unambiguously parsed
	   from the end of the string by inserting the length of the byte string after the byte string
       representation of x.
	 * @param x, integer x
	 * @return right_encoded byte array
	 */
	public static byte[] right_encode(int x) {
		int n = 0;
		long two_to_eight = (int) Math.pow(2, 8);
		while (Math.pow(two_to_eight, n) <= x) {
			n++;
		}
		if (n == 0) {
			n = 1;
		}
		byte[] byte_string = new byte[n + 1];
		for (int i = 1; i <= n; i++) {
			int x_i = x >> (8 * (i - 1));
			byte_string[i - 1] = (byte) x_i;
			
		}
		byte_string[n] = (byte) n;
		return byte_string;
	}
	
	/**
	 * Encodes the integer x as a byte string in a way that can be unambiguously parsed
       from the beginning of the string by inserting the length of the byte string before the byte string
       representation of x.
	 * @param x, integer x
	 * @return left_encoded byte array
	 */
	public static byte[] left_encode(int x) {
		int n = 0;
		long two_to_eight = (int) Math.pow(2, 8);
		while (Math.pow(two_to_eight, n) <= x) {
			n++;
		}
		if (n == 0) {
			n = 1;
		}
		byte[] byte_string = new byte[n + 1];
		byte_string[0] = (byte) n;
		for (int i = 1; i <= n; i++) {
			int x_i = x >> (8 * (i - 1));
			byte_string[i] = (byte) x_i;
		}
		return byte_string;
	}

	/**
	 * Encodes bit strings in a way that may be parsed unambiguously from the beginning of the string, S.
	 * @param S, the byte array
	 * @return, result after performing the encode string algorithm as defined in the NIST Special Publication 800-185 section 2.3
	 */
	public static byte[] encode_string(byte[] S) {
		byte[] left_encode_byte_string = left_encode(S.length * 8);
		if (S.length == 0) {
			return left_encode_byte_string;
		}
		return concat_bytes(left_encode_byte_string, S);
	}
	
	
	/**
	 * Prepends an encoding of the integer w to an input string X, then pads the result with zeros until result is multiple of 8.
	 * @param X, the input string
	 * @param w, integer w
	 * @return result after performing bytepad according to the definition in NIST Special Publication 800-185 section 2.3
	 * 
	 * Reference: https://stackoverflow.com/questions/2183240/java-integer-to-byte-array
	 */
	public static byte[] bytepad(byte[] X, int w) {
		byte[] left_encode_w = left_encode(w);
		byte[] z = concat_bytes(left_encode_w, X);
		int padding = w - (z.length % w);
		byte[] int_to_byte = {
	            (byte)(padding >>> 24),
	            (byte)(padding >>> 16),
	            (byte)(padding >>> 8),
	            (byte)padding
	    };
		return concat_bytes(z, int_to_byte);
	}
	
	/**
	 * Calculates a substring of the input string
	 * @param X, the input string
	 * @param a, the starting index, inclusive
	 * @param b, the ending index (exclusive)
	 * @return, X[a:b]
	 */
	public byte[] substring(byte[] X, int a, int b) {
		if (a >= b || a >= X.length) {
			return new byte[] {};
		} else if (b <= X.length) {
			return Arrays.copyOfRange(X, a, b);
		} else {
			return Arrays.copyOfRange(X, a, X.length);
		}
	}
	
	/**
	 * Concats the two input strings.
	 * @param X, first input string 
	 * @param Y, second input string
	 * @return X | Y, or concatenation of X and Y.
	 */
	public static byte[] concat_bytes(byte[] X, byte[] Y) {
		byte[] concat = new byte[X.length + Y.length];
		for (int i = 0; i < X.length; i++) {
			concat[i] = X[i];
		}
		for (int i = X.length; i < concat.length; i++) {
			concat[i] = Y[i - X.length];
		}
		return concat;
	}
}
