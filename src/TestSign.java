import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

public class TestSign {

	public static void main(String[] args) {
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

		
			
