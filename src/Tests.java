import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

public class Tests {

	public static void main(String[] args) {
		System.out.println("Testing token signatures...");
		tokenTests();
		System.out.println("Testing encrypted envelopes...");
		envelopeTests();
	}

	public static void envelopeTests() {
		String plainMessage = "env-test1";
		ArrayList<String> plainObj = new ArrayList<>();
		plainObj.add("testItem1");
		plainObj.add("testItem2");
		Envelope test1 = new Envelope(plainMessage);
		test1.addObject(plainObj);
		SealedObject test1Secure = null;
		SecretKey AESkey = null;
		KeyGenerator keyGen = null;
		Cipher cipher = null;
		try {
			keyGen = KeyGenerator.getInstance("AES", "BC");
			keyGen.init(256, new SecureRandom());
			AESkey = (SecretKey)keyGen.generateKey();
			test1Secure = test1.encrypted(AESkey);
			System.out.println("Successfully sealed envelope (AES).");
		} catch (Exception e) {
			System.err.println("Error in AES sealing: " + e);
			System.exit(1);
		}			
		try {
			Envelope unsealed = (Envelope)test1Secure.getObject(AESkey);
			if (plainMessage.equals(unsealed.getMessage())) {
				System.out.println("Unsealed message matches!");
			} else {
				System.out.println("Unsealed message differs: " + unsealed.getMessage());
			}
			if (plainObj.equals((ArrayList<String>)(unsealed.getObjContents().get(0)))){
				System.out.println("Unsealed object matches!");
			} else {
				System.out.println("Unsealed object differs.");
			}
		} catch (Exception e) {
			System.err.println("Error in AES unsealing: " + e);
			System.exit(1);
		}
	}
	public static void tokenTests() {
		Security.addProvider(new BouncyCastleProvider());
		String gsName = "testGS";
		String uName = "testUser";
		ArrayList<String> groups = new ArrayList<>();
		groups.add("testGroup1");
		groups.add("testGroup2");
		Token tokTest = new Token(gsName, uName, groups);
		
		KeyPairGenerator keyPairGen = null;
		KeyPair pair = null;
		
		//Gen keypair
		try {
			keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
			keyPairGen.initialize(1024, new SecureRandom());

			pair = keyPairGen.generateKeyPair();
		} catch (Exception e) {
			System.err.println("Key generation: " + e);
			System.exit(1);
		}
		
		System.out.println("Token String: " + tokTest.toString());
		//Sign token
		try {
			tokTest.tokSign(pair.getPrivate());
		} catch (Exception e) {
			System.err.println("Token signing: " + e);
		}

		System.out.println("Signing successful, verifying...");
		//Verify token signature
		try {
			if(tokTest.tokVerify(pair.getPublic())) {
				System.out.println("Verified!");
			} else {
				System.out.println("Token could not be verified.");
			}
		} catch (Exception e) {
			System.err.println("Token verification: " + e);
		}
		
		System.out.println("All tests completed! Exiting...");
		System.exit(0);
	}
}

		
			
