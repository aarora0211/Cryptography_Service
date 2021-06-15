/**
 * Name: Akshit Arora
 * Date: 06/03/2021
 * Class: TCSS 487, Spring 2021
 * 
 * Java Implementation of SHA3
 *  
 *  References:
 *  SHA3 Implementation by Markku-Juhani: https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 *  NIST Special Publication 800-185: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
 *  Stackoverflow, reference mentioned more clearly at specific methods
 *  
 */

package crypto_package;

import java.util.Arrays;

public class Sha3 {

		byte[] st_b = new byte[200]; // byte array 
		int mdlen; // output length
		int rsiz; //block size
		int pt; // pointer
		
		private static final int KECCAKF_ROUNDS = 24;
		
		private final long[] keccakf_rndc = new long[] {
				0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
				0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
				0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
				0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
				0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
				0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
				0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
				0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
		};
		
		private final int[] keccakf_rotc = new int[] {
		        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
		        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
		};
		
		private final int[] keccakf_piln = new int[] {
		        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
		        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1		
		};
		
		
		// Initialize the context for SHA3
		public Sha3(int mdlen) {
			Arrays.fill(st_b, (byte)0);
			this.mdlen = mdlen;
			rsiz = 200 - 2 * mdlen;
			pt = 0;
		}
		
		/**
		 * Compute the keccak-f of the byte array
		 * 
		 * @param b, the byte array
		 * reference: https://stackoverflow.com/questions/1586882/how-do-i-convert-a-byte-array-to-a-long-in-java
		 */
		public void sha3_keccakf(byte[] b) {
			long[] st = new long[25];
			long[] bc = new long[5];
			
			
			// endianess conversion. this is redundant on little-endian targets
			for (int i = 0; i < 25; i++) {
				int j = i * 8;
				st[i] = (((long)b[j] & 0xFFL))           | (((long)b[j + 1] & 0xFFL) <<  8) |
						(((long)b[j + 2] & 0xFFL) << 16) | (((long)b[j + 3] & 0xFFL) << 24) |
						(((long)b[j + 4] & 0xFFL) << 32) | (((long)b[j + 5] & 0xFFL) << 40) |
						(((long)b[j + 6] & 0xFFL) << 48) | (((long)b[j + 7] & 0xFFL) << 56);
	        }
			
			
			// actual iteration
			for (int r = 0; r < KECCAKF_ROUNDS; r++) {
				
				// Theta
				for (int i = 0; i < 5; i++) {
					bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
				}
				
				for (int i = 0; i < 5; i++) {
					long t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
					for (int j = 0; j < 25; j+=5) {
						st[j + i] ^= t;
					}
				}
				
				// Rho Pi
				long t = st[1];
				for (int i = 0; i < 24; i++) {
					int j = keccakf_piln[i];
					bc[0] = st[j];
					st[j] = ROTL64(t, keccakf_rotc[i]);
					t = bc[0];
				}
				
				// Chi
				for (int j = 0; j < 25; j+=5) {
					for (int i = 0; i < 5; i++) {
						bc[i] = st[j + i];
					}
					for (int i = 0; i < 5; i++) {
						st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
					}
				}
				
				// Iota
				st[0] ^= keccakf_rndc[r];
			}
				
	        // endianess conversion. this is redundant on little-endian targets
	        for (int i = 0; i < 25; i++) {
	        	int j = i * 8;
	            long t = st[i];
	            b[j] = (byte) (t & 0xFF);
	            b[1 + j] = (byte) ((t >> 8) & 0xFF);
	            b[2 + j] = (byte) ((t >> 16) & 0xFF);
	            b[3 + j] = (byte) ((t >> 24) & 0xFF);
	            b[4 + j] = (byte) ((t >> 32) & 0xFF);
	            b[5 + j] = (byte) ((t >> 40) & 0xFF);
	            b[6 + j] = (byte) ((t >> 48) & 0xFF);
	            b[7 + j] = (byte) ((t >> 56) & 0xFF);
	        }
		}
		
		/**
		 *Update state with more data
		 * @param data, input
		 * @param len, the length of the data
		 */
	    public void sha3_update(byte[] data, int len) {
	    	
	        int i, j = pt;
	        for (i = 0; i < len; i++) {
	            st_b[j++] ^= data[i];
	            if(j >= rsiz) {
	            	sha3_keccakf(st_b);
	                j = 0;
	            }
	        }
	        pt = j;
	    }
		
		// SHAKE128 and SHAKE256 extensible-output functionality
	    
		public void shake_xof(boolean cShake) {
			if (cShake)
				st_b[pt] ^= 0x04;
			else
				st_b[pt] ^= 0x1F;
			st_b[rsiz - 1] ^= (byte) 0x80;
			sha3_keccakf(st_b);
			pt = 0;
		}
				
		public void shake_out(byte[] out, int len) {
			int i, j = pt;
			for (i = 0; i < len; i++) {
				if (j >= rsiz) {
					sha3_keccakf(st_b);
					j = 0;
				}
				out[i] = st_b[j++];
			}
			pt = j;
		}
		
		
		/**
		 * Performs a left circular shift for unsigned long
		 * Reference: https://stackoverflow.com/questions/22325648/what-is-the-equivalent-of-rotl64-under-gcc
		 * @param l, unsigned 64 bit long
		 * @param i, integer shift value
		 * @return, the left circular shift of the long parameter.
		 */
		private long ROTL64(long l, int i) {
			// TODO Auto-generated method stub
			return ((l << i) | (l >>> (64 - i)));
		}
		

}
