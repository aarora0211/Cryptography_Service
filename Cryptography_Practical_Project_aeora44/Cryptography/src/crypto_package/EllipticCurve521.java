/**
 * Name: Akshit Arora
 * Date: 06/03/2021
 * Class: TCSS 487, Spring 2021
 * 
 * Elliptic Point Cryptography.
 * Java class implementing points on E521 or the Edwards curve.
 * Curve Equation: x^2 + y^2 = dx^2y^2, d = -376014
 * Functions implemented according to the specifications in the project description.
 * References:
 * Appendix in the project description.
 * 
 * 
 */


package crypto_package;

import java.math.BigInteger;

public class EllipticCurve521 {

	
	// Mersenne prime defining the finite field Fp
	public static final BigInteger p = BigInteger.TWO.pow(521).subtract(BigInteger.ONE);
	
	// Constant d for the curve equation
	public static final BigInteger d = BigInteger.ZERO.subtract(BigInteger.valueOf(376014));
	
	// constant r
	public static final BigInteger r = BigInteger.TWO.pow(519).subtract(new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765"));
	
	// X coordinate of the curve
	private BigInteger x;
	
	// y coordinate of the curve
	private BigInteger y;
	
	/**
	 *  Default constructor defining the neutral element
	 */
	public EllipticCurve521() {
		this.x = BigInteger.ZERO;
		this.y = BigInteger.ONE;
	}
	
	/**
	 * Initializes the EllipticCurve521 with the passed x and y parameters
	 * @param x, the x coordinate
	 * @param y, the y coordinate
	 */
	public EllipticCurve521(BigInteger x, BigInteger y) {
		this.x = x;
		this.y = y;
	}
	
	/**
	 * constructor for a curve point from its 𝑥 coordinate and the least significant bit of y
	 * @param x
	 */
	public EllipticCurve521(BigInteger x) {
		this.x = x;
		this.y = getLeastSigBitY(x);
	}
	
	/**
	 * getter method for the x coordinate
	 * @return this.x
	 */
	public BigInteger getX() {
		return this.x;
	}
	
	/**
	 * getter method for the y coordinate
	 * @return this.y
	 */
	public BigInteger getY() {
		return this.y;
	}
	
	/**
	 * returns y coordinate value from the x coordinate and the least significant bit of y
	 * @param x, the x coordinate value
	 * @return y, the calculate y coordinate value
	 */
	private BigInteger getLeastSigBitY(BigInteger x) {
		BigInteger num = BigInteger.ONE.subtract(x.pow(2));
		BigInteger den = BigInteger.ONE.subtract(d.multiply(x.pow(2)));
		return sqrt(num.multiply(den.modInverse(p)), p, false);
	}

	/**
	 * returns whether the passed elliptic curve is equal to the current point or not
	 * @param other, the Elliptic Curve point to compare
	 * @return true, if the two points are equal, false otherwise
	 */
	public boolean equals(EllipticCurve521 other) {
		return this.x.equals(other.x) && this.y.equals(other.y);
	}
	
	/**
	 * returns the opposite of the passed point
	 * @param pt, the passed EllipticCurve521 point
	 * @return the opposite of the passed point
	 */
	public EllipticCurve521 oppositePoint(EllipticCurve521 pt) {
		return new EllipticCurve521(pt.x.negate(), pt.y);
	}
	
	/**
	 * Adds the two Elliptic curve points.
	 * @param other, the EllipticCurve521 point to be added.
	 * @return the sum of the two points.
	 */
	public EllipticCurve521 add(EllipticCurve521 other) {
		BigInteger numX = x.multiply(other.y).add(y.multiply(other.x)).mod(p);
		BigInteger numY = y.multiply(other.y).subtract(x.multiply(other.x)).mod(p);
		BigInteger denX = BigInteger.ONE.add(d.multiply(x).multiply(other.x).multiply(y).multiply(other.y)).mod(p).modInverse(p);
		BigInteger denY = BigInteger.ONE.subtract(d.multiply(x).multiply(other.x).multiply(y).multiply(other.y)).mod(p).modInverse(p);
		BigInteger newX = numX.multiply(denX).mod(p);
		BigInteger newY = numY.multiply(denY).mod(p);
		return new EllipticCurve521(newX, newY);
	}
	
	/**
	 * Multiplies the Elliptic Curve point with the passed scalar value, according to the pseudo code in the project specifications.
	 * @param scalar, the scalar value
	 * @return, the result after multiplying the curve point with the scalar value.
	 */
	public EllipticCurve521 multiplyScalor(BigInteger scalar) {
		if (scalar.equals(BigInteger.ZERO)) {
			return new EllipticCurve521(BigInteger.ZERO, BigInteger.ONE);
		}
		EllipticCurve521 V = new EllipticCurve521(x, y);
		for (int i = scalar.bitLength() - 2; i >= 0; i--) {
			V = V.add(V);
			if (scalar.testBit(i)) {
				V = V.add(this);
			}
		}
		return V;
	}
	
	/**
	* Compute a square root of v mod p with a specified
	* least significant bit, if such a root exists.
	*
	* @param v the radicand.
	* @param p the modulus (must satisfy p mod 4 = 3).
	* @param lsb desired least significant bit (true: 1, false: 0).
	* @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
	* if such a root exists, otherwise null.
	*/
	public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
	 assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
	 if (v.signum() == 0) {
	 return BigInteger.ZERO;
	 }
	 BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
	 if (r.testBit(0) != lsb) {
	 r = p.subtract(r); // correct the lsb
	 }
	 return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
	}
	
	/**
	 * Testing the EllipticCurve521 class according to the specifications in the project description
	 * Please uncomment the main method and run the file for testing.
	 * @param args
	 */
//	public static void main(String[] args) {
//	    EllipticCurve521 g = new EllipticCurve521(new BigInteger("4"));
//		System.out.println("G    -> " + g.x.toString() + "      " + g.y.toString());
//		
//		// 0*G = O
//		EllipticCurve521 g_0 = g.multiplyScalor(BigInteger.ZERO);
//		System.out.println("G x 0    -> " + g_0.x.toString() + "      " + g_0.y.toString());
//		
//		// 1*G = G
//		EllipticCurve521 g_1 = g.multiplyScalor(BigInteger.ONE);
//		System.out.println("G x 1    -> " + g_1.x.toString() + "      " + g_1.y.toString());
//		
//		// 2*G = G + G
//		EllipticCurve521 g_2_mult = g.multiplyScalor(BigInteger.TWO);
//		EllipticCurve521 g_2_add = g.add(g);
//		System.out.println("G + G == G x 2    ->" + g_2_mult.equals(g_2_add));
//		
//		// 4*G = 2*(2*G)
//		EllipticCurve521 g_4_mult = g.multiplyScalor(BigInteger.valueOf(4));
//		EllipticCurve521 g_2_2 = g_2_mult.multiplyScalor(BigInteger.TWO);
//		System.out.println("4 * G == 2*G x 2    ->" + g_2_2.equals(g_4_mult));
//		
//		// 4*G ≠ O
//		System.out.println("4 * G != 0    ->" + !g_4_mult.equals(new EllipticCurve521(BigInteger.ZERO, BigInteger.ONE)));
//		
//		// r*G = O
//		System.out.println("r * G = 0    ->" + g.multiplyScalor(r).equals(new EllipticCurve521(BigInteger.ZERO, BigInteger.ONE)));
//
//	}
}
