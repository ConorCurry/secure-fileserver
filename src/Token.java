import java.util.*;
import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.io.*;

public class Token implements UserToken, java.io.Serializable{

    private String gsName;
    private String username;
    private ArrayList<String> accessibleGroups;
    private static final long serialVersionUID = -7726335089122193103L;
	private byte[] signature;
	private long created_time;
	private byte[] time_encrypted;
	private ArrayList<SecretKey> file_keys;

    public Token(String gsName, String username, ArrayList<String> accessibleGroups) {
        this.gsName = gsName;
        this.username = username;
		this.signature = null;
        if(accessibleGroups != null && !accessibleGroups.isEmpty())
            this.accessibleGroups = new ArrayList<String>(accessibleGroups); //new concatenation; 
        else
            this.accessibleGroups = new ArrayList<String>();
    }

    public Token(String gsName, String username, ArrayList<String> accessibleGroups, ArrayList<SecretKey> keys){
        this.gsName = gsName;
        this.username = username;
		this.signature = null;
        if(accessibleGroups != null && !accessibleGroups.isEmpty())
            this.accessibleGroups = new ArrayList<String>(accessibleGroups); //new concatenation; 
        else
            this.accessibleGroups = new ArrayList<String>();
        created_time = (new Date()).getTime();
        this.file_keys = new ArrayList<SecretKey>(keys);
    }

    public Token(String gsName, String username, ArrayList<String> accessibleGroups, PublicKey fileserver_key) {
        this.gsName = gsName;
        this.username = username;
		this.signature = null;
        if(accessibleGroups != null && !accessibleGroups.isEmpty())
            this.accessibleGroups = new ArrayList<String>(accessibleGroups); //new concatenation; 
        else
            this.accessibleGroups = new ArrayList<String>();
        this.time_encrypted = encrypte_time(fileserver_key);
    }

    public long getCreatedTime()
    {
    	return created_time;
    }

    public String getIssuer() {
        return this.gsName;        
    }
    public String getSubject() {
        return this.username;
    }
    public List<String> getGroups() {
        return this.accessibleGroups;
    }

    public List<SecretKey> getKeys()
    {
    	return this.file_keys;
    }
    
    public byte[] getEncryptedTime()
    {
    	return this.time_encrypted;
    }
	
	@Override
	public String toString() {
		//CAUTION: THIS REQUIRES THAT '&' AND ',' BE BLACKLISTED FROM USERNAMES, GS NAMES, AND GROUPNAMES
		StringBuilder strified = new StringBuilder();
		strified.append(this.username + "&" + this.gsName + "&");
		for(String group : this.accessibleGroups) {
			strified.append(group);
			strified.append('+');
		}
		return strified.toString();
	}

	public void tokSign(PrivateKey privateKey) throws InvalidKeyException, SignatureException {
		Signature sig = null;
		try {
			sig = Signature.getInstance("SHA256withRSA", "BC");
		} catch (Exception e) {
			System.err.println(e);
			return;
		}

   		sig.initSign(privateKey);
		sig.update(this.toString().getBytes()); //signing automatically hashes
	   	this.signature = sig.sign();
	}

	public boolean tokVerify(PublicKey publicKey) throws InvalidKeyException, SignatureException {
		Signature sig = null;
		try {
			sig = Signature.getInstance("SHA256withRSA", "BC");
		} catch (Exception e) {
			System.err.println(e);
			return false;
		}

		sig.initVerify(publicKey);
		sig.update(this.toString().getBytes()); //signing automatically hashes
		if(sig.verify(signature)) {
			return true;
		} else {
			return false;
		}
	}

	private byte[] encrypte_time(PublicKey serverPubkey)
	{
		try
		{
			Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
		 	cipher.init(Cipher.ENCRYPT_MODE, serverPubkey);
		 	ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DataOutputStream dos = new DataOutputStream(baos);
			dos.writeLong((new Date()).getTime());
			dos.close();
			byte[] longBytes = baos.toByteArray();
		 	return cipher.doFinal(longBytes);
		}
		catch(Exception e)
		{
			System.out.println("Can't encrypt time with file server's public key");
			return null;
		}
	}
}
