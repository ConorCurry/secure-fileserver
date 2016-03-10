import java.util.ArrayList;
import java.io.Serializable;
import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import java.security.*;


public class Envelope implements Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;
	private ArrayList<Object> objContents = new ArrayList<Object>();
	
	public Envelope(String text)
	{
		Security.addProvider(new BouncyCastleProvider());
		msg = text;
	}
	
	public String getMessage()
	{
		return msg;
	}
	
	public ArrayList<Object> getObjContents()
	{
		return objContents;
	}
	
	public void addObject(Object object)
	{
		objContents.add(object);
	}

	//encrypt with different modes 
	public void encrypted(SecretKey secretKey) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			//clean up all the fields and make the sealedobject as the only field 
			msg = "";
			objContents = new ArrayList<Object>();

			objContents.add(new SealedObject(this, cipher));
		} catch (Exception e) {
			System.err.println("ENVELOPE ENCRYPTION FAILED (Sym): " + e);
		}
	}

	public void encrypted(PublicKey pubkey) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, pubkey);

			//clean up all the fields and make the sealedobject as the only field 
			msg = "";
			objContents = new ArrayList<Object>();
			
			objContents.add(new SealedObject(this, cipher));
		} catch (Exception e) {
			System.err.println("ENVELOPE ENCRYPTION FAILED (RSA): " + e);
		}
	}

	//decrypt with different modes 
	public Envelope decrypted(SecretKey secretKey)
	{
		Cipher cipher = null;
		try {
			SealedObject response = (SealedObject)objContents.get(0);
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			return (Envelope)response.getObject(cipher);
		} catch (Exception e) {
			System.err.println("ENVELOPE ENCRYPTION FAILED (RSA): " + e);
			return null;
		}
	}

	public Envelope decrypted(PrivateKey privkey)
	{
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, privkey);
			SealedObject response = (SealedObject)objContents.get(0);
			return (Envelope)response.getObject(cipher);
		} catch (Exception e) {
			System.err.println("ENVELOPE ENCRYPTION FAILED (RSA): " + e);
			return null;
		}
	}

}
