/* FileClient provides all the client functionality regarding the file server */

import java.io.*;
import java.util.*;
import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.math.BigInteger;
import java.security.spec.X509EncodedKeySpec;

public class FileClient extends Client implements FileClientInterface {

	private static final String RSA_METHOD = "RSA/NONE/OAEPWithSHA256AndMGF1Padding";
	private static final String SYM_METHOD = "AES/CBC/PKCS5Padding";
	private static SecretKey symKey = null;
	private static SecretKey identity_key = null;
	private static int t = 0;

	public PublicKey getFSkey()
	{
		try
		{
			Envelope message = new Envelope("GetPubKey");
			output.writeObject(message);

			Envelope response = (Envelope)input.readObject();
			if(response.getMessage().equals("OK"))
				return (PublicKey)response.getObjContents().get(0);
			else
				return null;
		}
		catch(Exception e)
		{
			System.err.println("Error getting PublicKey: " + e);
			return null;
		}
	}

	public boolean authenticate(UserToken token, PublicKey usrPubKey, PrivateKey usrPrivKey, PublicKey serverKey) {
		KeyPairGenerator keyPairGen = null;
		Cipher cipher = null;
		SecureRandom srng = new SecureRandom();
		
		//generate two big integers for DH
		BigInteger p, g;
		int bitLength = 512;
		SecureRandom rnd = new SecureRandom();
		p = BigInteger.probablePrime(bitLength, rnd);
		g = BigInteger.probablePrime(bitLength, rnd);
		
		byte[] sigBytes = null;
		byte[] dhPublic_bytes = null;
		PrivateKey dhPrivate = null;
		
		try
		{
			//generate DH key pairs. 
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "BC");

		    DHParameterSpec param = new DHParameterSpec(p, g);
		    kpg.initialize(param);

		    KeyPair kp = kpg.generateKeyPair();

		    dhPrivate = kp.getPrivate();
		    PublicKey dhPublic = kp.getPublic();
		    dhPublic_bytes = dhPublic.getEncoded();
		    //we need to sign this value. 

		    //generate signature
			Signature sig = Signature.getInstance("RSA", "BC");
			sig.initSign(usrPrivKey, new SecureRandom());
			//update encrypted data to be signed and sign the data 
			sig.update(dhPublic_bytes);
			sigBytes = sig.sign();
		}
		catch(Exception ex)
		{
			System.out.println("Error in generating DH pairs");
			ex.printStackTrace();
		}

		//STAGE1 -- Initialize connection, prepare challenge
		Envelope auth = new Envelope("AUTH");
		byte[] p_bytes = p.toByteArray();
		byte[] g_bytes = g.toByteArray();
		byte[] key_bytes = usrPubKey.getEncoded();

		//need enough space for two items encrpyted with the 3072 bit server public key
		//encrypt packed bytes with group server's public key
		try {
			cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, serverKey);
			auth.addObject(cipher.doFinal(p_bytes));
			auth.addObject(cipher.doFinal(g_bytes));
			auth.addObject(cipher.doFinal(Arrays.copyOfRange(key_bytes, 0, 192)));
			auth.addObject(cipher.doFinal(Arrays.copyOfRange(key_bytes, 192, key_bytes.length)));
			auth.addObject(dhPublic_bytes); //dh
			auth.addObject(sigBytes);//signed dh  
			output.writeObject(auth);
		} catch (Exception ex) {
			System.err.println("Encrypting Challenge Failed (RSA): " + ex);
			ex.printStackTrace();
			return false;
		}
		
		//STAGE2 -- Validate server response & retrieve server's dh public key and generate a shared keys
		Envelope env = null;
		try 
		{
			env = (Envelope)input.readObject();
		} 
		catch (Exception ex) 
		{
			System.err.println("Error recieving authentication response: " + ex);
			ex.printStackTrace();
			return false;
		}

		if(env != null && env.getMessage().equals("AUTH")) 
		{
			try
			{
				byte[] oDHpubKeyByte = (byte[])(env.getObjContents().get(0));
				byte[] signed_oDHbyte = (byte[])(env.getObjContents().get(1));

				Signature sig = Signature.getInstance("RSA", "BC");
				sig.initVerify(serverKey);
	    		//update decrypted data to be verified and verify the data
	    		sig.update(oDHpubKeyByte);
	    		boolean verified = sig.verify(signed_oDHbyte);
	    		if(verified)
	    		{
					KeyFactory kf = KeyFactory.getInstance("DH", "BC");
					X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(oDHpubKeyByte);
           			PublicKey theirPublicKey = kf.generatePublic(x509Spec);
           			KeyAgreement ka = KeyAgreement.getInstance("DH");
			        ka.init(dhPrivate);
			        ka.doPhase(theirPublicKey, true);
			        symKey = ka.generateSecret("AES"); //RETRIEVE AN AES KEY. for future use.    
	    		}
			} 
			catch (Exception e) 
			{
				System.err.println("Error in retreiving session key: ");
				e.printStackTrace();
				return false;
			}		
		} 
		else 
		{
			System.err.println("Invalid server response");
			return false;
		}

		try
		{
			Envelope idenEnv = new Envelope("IDENTITY");
		    output.writeObject(idenEnv.encrypted(symKey));

			env = (Envelope)((SealedObject)input.readObject()).getObject(symKey);
			if(env != null && env.getMessage().equals("OK"))
			    identity_key = (SecretKey)env.getObjContents().get(0);
			else
			{
				System.err.println("Invalid server response FOR GETTING IDENTITY KEY");
				return false;
			}
		}
		catch (Exception e) 
		{
				System.err.println("Error in retreiving identity key: ");
				e.printStackTrace();
				return false;
		}		
		return true;
	}

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
	    env.addObject(remotePath);
	    env.addObject(token);
	    try {
			output.writeObject(env.encrypted(symKey));
		    env = (Envelope)( (SealedObject)input.readObject() ).getObject(symKey);
			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);				
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}			
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	    	
		return true;
	}

	public boolean download(String sourceFile, String destFile, String group, UserToken token, ArrayList<SecretKey> key_list) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}
		
				File file = new File(destFile);
			    try {
			    				
				
				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);
					    
					    Envelope env = new Envelope("DOWNLOADF"); //Success
					    env.addObject(sourceFile);
					    env.addObject(token);
					    output.writeObject(env.encrypted(symKey)); 
						
					    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			 			SecretKey decrypt_key = null;
			 			byte[] IVarray = Arrays.copyOf(convertToBytes(group), 16);
			 			int i = 0;

			 			env = (Envelope)((SealedObject)input.readObject()).getObject(symKey);

						while (env.getMessage().compareTo("CHUNK")==0) { 
								if(i == 0) decrypt_key = key_list.get((Integer)env.getObjContents().get(2));
								cipher.init(Cipher.DECRYPT_MODE, decrypt_key, new IvParameterSpec(IVarray));
								byte[] decrypted_data = cipher.doFinal((byte[])env.getObjContents().get(0));
								fos.write(decrypted_data, 0, (Integer)env.getObjContents().get(1));
								System.out.printf(".");
								env = new Envelope("DOWNLOADF"); //Success
								output.writeObject(env.encrypted(symKey));
								env = (Envelope)((SealedObject)input.readObject()).getObject(symKey);	
								i++;	
						}										
						fos.close();
						
					    if(env.getMessage().compareTo("EOF")==0) {
					    	 fos.close();
							 System.out.printf("\nTransfer successful file %s\n", sourceFile);
							 env = new Envelope("OK"); //Success
							 output.writeObject(env.encrypted(symKey));
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return false;								
						}
				    }    
				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }
								
			
			    } catch (IOException e1) {
			    	
			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	System.out.println(e1.getMessage());
			    	e1.printStackTrace();
			    	return false;
			    
					
				} catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				} catch (Exception ex) {
					ex.printStackTrace();
				}
				 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token); //Add requester's token
			 if(symKey == null) {
				 System.err.println("NULL SYMKEY");
			 }
			 output.writeObject(message.encrypted(symKey)); 
			 
			 try {
				 e = (Envelope)((SealedObject)input.readObject()).getObject(symKey);
			 } catch (Exception ex) {
				 System.err.println("Unable to read client message: " + e);
				 return null;
			 }
			 
			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 { 
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	}

	public boolean upload(String sourceFile, String destFile, String group, UserToken token, ArrayList<SecretKey> key_list) {
			
		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }
		
		try
		 {
			 
			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token
			 message.addObject(new Integer(key_list.size()-1)); //add the index of key used 
			 output.writeObject(message.encrypted(symKey));
			
			 
			 FileInputStream fis = new FileInputStream(sourceFile);
			 
			 env = (Envelope)((SealedObject)input.readObject()).getObject(symKey);
			 
			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 { 
				System.out.printf("Meta data upload successful\n");
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }

			 Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			 SecretKey encrypt_key = key_list.get(key_list.size() - 1);
			 byte[] IVarray = Arrays.copyOf(convertToBytes(group), 16);
			 
			 do {
				 	byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}
					//encrypt buf first 
					cipher.init(Cipher.ENCRYPT_MODE, encrypt_key, new IvParameterSpec(IVarray));
					byte[] encrypted_data = cipher.doFinal(buf);
					message.addObject(encrypted_data);
					message.addObject(new Integer(n));
					
					output.writeObject(message.encrypted(symKey));
					
					env = (Envelope)((SealedObject)input.readObject()).getObject(symKey);					
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				
				message = new Envelope("EOF");
				output.writeObject(message.encrypted(symKey));
				
				env = (Envelope)((SealedObject)input.readObject()).getObject(symKey);
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {
					
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}

	private byte[] convertToBytes(Object object){
 		try{ 
    	   	ByteArrayOutputStream bos = new ByteArrayOutputStream();
         	ObjectOutput out = new ObjectOutputStream(bos);
        	out.writeObject(object);
        	bos.close();
        	out.close();
        	return bos.toByteArray();
    	} 
    	catch (Exception byte_exception)
    	{
    		System.out.println("Can't convert object to a byte array");
    		return null;
    	}
	}
}

