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

	public SealedObject encrypted(SecretKey secretKey) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);

			return new SealedObject(this, cipher);
		} catch (Exception e) {
			e.printStackTrace(System.err);
			System.err.println("ENVELOPE ENCRYPTION FAILED (Sym): " + e);
			return null;
		}
	}
}
