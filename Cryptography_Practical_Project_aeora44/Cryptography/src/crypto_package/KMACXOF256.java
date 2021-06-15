/**
 * Name: Akshit Arora
 * Date: 06/03/2021
 * Class: TCSS 487, Spring 2021
 * 
 * Java Implementation of KMACXOF256
 *  
 *  References:
 *  NIST Special Publication 800-185: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
 *  Stackoverflow
 *  
 */


package crypto_package;

public class KMACXOF256 extends InternalFunctions {	

	
	/**
	 * Calculates the KMACXOF256
	 * 
	 * @param K, key bit string of any length, including zero.
	 * @param X, main input bit string. It may be of any length, including zero.
	 * @param L, integer representing the requested output length in bits.
	 * @param S, customization bit string. The user selects this string to define a variant of the function. When no customization is desired, S is set to the empty string.
	 * @return, result of KMACXOF256
	 */
	public static byte[] KMACXOF256_CALCULATOR(byte[] K, byte[] X, int L, byte[] S) {
		byte[] newX = concat_bytes(concat_bytes(bytepad(encode_string(K),136), X), right_encode(0));
		return cSHAKE256(newX, L, "KMAC".getBytes(), S);
	}

	/**
	 * Calculates the cSHAKE256. Returns the output of Shake or Keccak
	 * 
	 * @param X, main input bit string. It may be of any length, including zero
	 * @param L, an integer representing the requested output length4 in bits.
	 * @param N,  a function-name bit string, used by NIST to define functions based on cSHAKE.
				  When no function other than cSHAKE is desired, N is set to the empty string.
	 * @param S,  a customization bit string. The user selects this string to define a variant of the
				  function. When no customization is desired, S is set to the empty string.
	 * @return
	 */
	private static byte[] cSHAKE256(byte[] X, int L, byte[] N, byte[] S) {
		boolean canUseCShake = false;
		Sha3 sha = new Sha3(32);
		byte[] out = new byte[L/8];
		if (N.length != 0 && S.length != 0) { // use cSHAKE
			canUseCShake = true;
			byte[] bytepad= bytepad(concat_bytes(encode_string(N), encode_string(S)), 136);
			sha.sha3_update(bytepad, bytepad.length);
		}
		sha.sha3_update(X, X.length);
		sha.shake_xof(canUseCShake);
		sha.shake_out(out, L/8);
		return out;
	}
}
