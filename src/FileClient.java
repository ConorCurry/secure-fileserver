/* FileClient provides all the client functionality regarding the file server */

import java.io.*;
import java.util.*;
import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;

public class FileClient extends Client implements FileClientInterface {

	private static final String RSA_METHOD = "RSA/NONE/OAEPWithSHA256AndMGF1Padding";
	private static final String SYM_METHOD = "AES/CBC/PKCS5Padding";
	private static SecretKey symKey;
	private static SecretKey identity_key;
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
		//64-bit random challenge
		byte[] rand = new byte[8];
		byte[] challenge;
		symKey = null;
		srng.nextBytes(rand);

		//STAGE1 -- Initialize connection, prepare challenge
		Envelope auth = new Envelope("AUTH");
		//concat nonce and user public key
		ByteArrayOutputStream concat = new ByteArrayOutputStream();
		byte[] encodedKey;
		try {
			concat.write(rand, 0 , 8);
			System.out.println("Rand: " + new String(rand));
			encodedKey = usrPubKey.getEncoded();
			System.out.println("EncKey len: " + encodedKey.length);
			concat.write(encodedKey, 0, encodedKey.length);
		} catch(Exception ex) {
			System.err.println("encoding error: " + ex);
			return false;
		}

		//need enough space for two items encrpyted with the 3072 bit server public key
		//encrypt packed bytes with group server's public key
		try {
			challenge = new byte[(3072/8) * 2];
			cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, serverKey);
			byte[] reqBytes = concat.toByteArray();
			System.out.println("reqBytes len: " + reqBytes.length);
			byte[] enc1 = cipher.doFinal(Arrays.copyOfRange(reqBytes, 0, reqBytes.length/2));
			byte[] enc2 = cipher.doFinal(Arrays.copyOfRange(reqBytes, reqBytes.length/2, reqBytes.length));
			System.arraycopy(enc1, 0, challenge, 0, enc1.length);
			System.arraycopy(enc2, 0, challenge, enc1.length, enc2.length);
			auth.addObject(challenge);
			output.writeObject(auth);
		} catch (Exception ex) {
			System.err.println("Encrypting Challenge Failed (RSA): " + ex);
			return false;
		}
		
		//STAGE2 -- Validate server response & retrieve session key
		Envelope env = null;
		try {
			env = (Envelope)input.readObject();
		} catch (Exception ex) {
			System.err.println("Error recieving authentication response: " + ex);
			return false;
		}
		System.out.println(env.getMessage());
		if(env != null && env.getMessage().equals("AUTH")) {
			try {
				MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
				//byte array decyption cipher
				cipher.init(Cipher.DECRYPT_MODE, usrPrivKey);
				byte[] resp = cipher.doFinal( (byte[])env.getObjContents().get(0) );
				//parse response bytes
				messageDigest.update(rand);
				int len = messageDigest.getDigestLength();
				byte[] challenge_resp = Arrays.copyOfRange(resp,0,len);
				
				if (!Arrays.equals(challenge_resp, messageDigest.digest())) {
					System.out.println("Server authenticity could not be verified");
					return false;
				}
				System.out.println("chal hash len: " + len);
				System.out.println("Resp len: " + resp.length);
				//retrieve AES256 session key
				symKey = (SecretKey)new SecretKeySpec(Arrays.copyOfRange(resp,len,len+32), "AES");
				identity_key = (SecretKey)new SecretKeySpec(Arrays.copyOfRange(resp,len+32,len+64), "HmacSHA256");
				byte[] tNonce = Arrays.copyOfRange(resp,len+64,len+68);
				t = (Integer)ByteBuffer.wrap(tNonce).getInt();
				t++;
				System.out.print("TimeNonce: " + t);
			} catch (Exception e) {
				System.err.println("Error in validating challenge response / retreiving session key (RSA): ");
				e.printStackTrace();
				return false;
			}			
		} else {
			System.err.println("Invalid server response");
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

