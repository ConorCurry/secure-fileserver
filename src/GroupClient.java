/* Implements the GroupClient Interface */

import java.util.*;
import java.io.*;
import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import java.security.*;
import java.nio.ByteBuffer;
import java.math.BigInteger;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class GroupClient extends Client implements GroupClientInterface {
 	 private static final String RSA_Method = "RSA/NONE/OAEPWithSHA256AndMGF1Padding";
	 private static final String AES_Method = "AES/CBC/PKCS5Padding";
	 private static SecretKey AES_key = null;
	 private static Key identity_key = null;
	 private static int t = 0;

	public PublicKey getGSkey()
	{
		try
		{
			Envelope message = new Envelope("GetPubKey");
			output.writeObject(message);
			System.out.println("send message to group server");

			Envelope response = (Envelope)input.readObject();
			System.out.println("get message to group server");
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
	 //send the user name and challenge to the server 
	 public boolean authenticate(String username, PrivateKey usrPrivKey, PublicKey serverPubkey)
	 {
	 	try
	 	{
	 		Security.addProvider(new BouncyCastleProvider());
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

			//need enough space for two items encrpyted with the 3072 bit server public key
			//encrypt packed bytes with group server's public key
			try 
			{
				cipher = Cipher.getInstance("RSA", "BC");
				cipher.init(Cipher.ENCRYPT_MODE, serverPubkey);
				auth.addObject(cipher.doFinal(p_bytes));
				auth.addObject(cipher.doFinal(g_bytes));
				auth.addObject(dhPublic_bytes); //dh
				auth.addObject(sigBytes);//signed dh
				auth.addObject(username);//username   
				output.writeObject(auth);
			} 
			catch (Exception ex) 
			{
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
					sig.initVerify(serverPubkey);
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
				        AES_key = ka.generateSecret("AES"); //RETRIEVE AN AES KEY. for future use.    
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
			    output.writeObject(idenEnv.encrypted(AES_key));

			    Envelope second_response = (Envelope)input.readObject();
				byte[] msg_combined_encrypted = convertToBytes((SealedObject)second_response.getObjContents().get(0));
				//retrieve identity key
				Envelope key_env = (Envelope)((SealedObject)(second_response.getObjContents().get(2))).getObject(AES_key);
				identity_key = (Key)key_env.getObjContents().get(0);
				Mac mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);
				//verify hmac
				byte[] rawHamc = mac.doFinal(msg_combined_encrypted);
				byte[] Hmac_passed = (byte[])second_response.getObjContents().get(1);
				if(Arrays.equals(rawHamc, Hmac_passed))
				{
					Envelope plaintext = (Envelope)((SealedObject)second_response.getObjContents().get(0)).getObject(AES_key);
					t = (Integer)plaintext.getObjContents().get(0);
					t++;
					if((plaintext.getMessage()).equals("OK"))
					{
						return true;
					}
				}
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
			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	 }

	 public UserToken getToken(String username)
	 {
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;
		 		 	
			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject((Integer)t); //always put t as the first one 
			t++;//increase t to keep order 
			message.addObject(username); //Add user name string

			Mac mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(identity_key);

			Envelope to_be_sent = new Envelope("REQ");
												
			Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
			SealedObject hmac_msg_sealed = new SealedObject(message, object_cipher);
			to_be_sent.addObject(hmac_msg_sealed);
													
			byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
			to_be_sent.addObject(rawHamc);

			output.reset();
			output.writeObject(to_be_sent);
			output.flush();
			output.reset();
		
			//Get the response from the server
			response = (Envelope)input.readObject();

			byte[] msg_combined_encrypted = convertToBytes((SealedObject)response.getObjContents().get(0));
			mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(identity_key);
			byte[] rawHamc_2 = mac.doFinal(msg_combined_encrypted);
			byte[] Hmac_passed = (byte[])response.getObjContents().get(1);
			if(Arrays.equals(rawHamc_2, Hmac_passed))
			{
				Envelope plaintext = (Envelope)((SealedObject)response.getObjContents().get(0)).getObject(AES_key);
				if((plaintext.getMessage()).equals("OK"))
				{
					//If there is a token in the Envelope, return it 
					ArrayList<Object> temp = plaintext.getObjContents();
				
					if(temp != null && temp.size() == 2)
					{
							int t_received = (Integer)temp.get(0);
							if(t_received == t)
							{
								token = (UserToken)temp.get(1);
								t++;
								return token;
							}
							else
							{
								System.out.println("The message is replayed/reordered.");
							}
					}
				}
				else
				{
					int t_received = (Integer)plaintext.getObjContents().get(0);
					if(t_received != t)
					{
						System.out.println("The message is replayed/reordered.");
					}
				}
			}										
			//System.out.printf("Server response msg: %s\n", response.getMessage());
			//Successful response
			t++;
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			t++;
			return null;
		}		
	 }
 	 
 	 public UserToken getToken(String username, ArrayList<String> groups)
	 {
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;
		 		 	
			//Tell the server to return a token.
			message = new Envelope("GET_SUBSET");
			message.addObject((Integer)t); //always put t as the first one 
			t++;//increase t to keep order 
			message.addObject(username); //Add user name string
			message.addObject(groups);

			Mac mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(identity_key);

			Envelope to_be_sent = new Envelope("REQ");
												
			Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
			SealedObject hmac_msg_sealed = new SealedObject(message, object_cipher);
			to_be_sent.addObject(hmac_msg_sealed);
													
			byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
			to_be_sent.addObject(rawHamc);

			output.reset();
			output.writeObject(to_be_sent);
			output.flush();
			output.reset();
		
			//Get the response from the server
			response = (Envelope)input.readObject();
			
			byte[] msg_combined_encrypted = convertToBytes((SealedObject)response.getObjContents().get(0));
			mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(identity_key);
			byte[] rawHamc_2 = mac.doFinal(msg_combined_encrypted);
			byte[] Hmac_passed = (byte[])response.getObjContents().get(1);
			if(Arrays.equals(rawHamc_2, Hmac_passed))
			{
				Envelope plaintext = (Envelope)((SealedObject)response.getObjContents().get(0)).getObject(AES_key);
				if((plaintext.getMessage()).equals("OK"))
				{
					//If there is a token in the Envelope, return it 
					ArrayList<Object> temp = plaintext.getObjContents();
				
					if(temp != null && temp.size() == 2)
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received == t)
						{
							token = (UserToken)temp.get(1);
							t++;
							return token;
						}
						else
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
				}
				else
				{
					int t_received = (Integer)plaintext.getObjContents().get(0);
					if(t_received != t)
					{
						System.out.println("The message is replayed/reordered.");
					}
				}

			}
			t++;
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			t++;
			return null;
		}		
	 }

	 public boolean createUser(String username, UserToken token, PublicKey to_be_added)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject((Integer)t); //always put t as the first one 
				t++;//increase t to keep order 
				message.addObject(username); //Add user name string
				message.addObject(token); //Add the requester's token
				message.addObject(to_be_added);

				Mac mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);

				Envelope to_be_sent = new Envelope("REQ");
												
				Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
				SealedObject hmac_msg_sealed = new SealedObject(message, object_cipher);
				to_be_sent.addObject(hmac_msg_sealed);
													
				byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
				to_be_sent.addObject(rawHamc);

				output.reset();
				output.writeObject(to_be_sent);
				output.flush();
				output.reset();
			
				response = (Envelope)input.readObject();
				
				byte[] msg_combined_encrypted = convertToBytes((SealedObject)response.getObjContents().get(0));
				mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);
				byte[] rawHamc_2 = mac.doFinal(msg_combined_encrypted);
				byte[] Hmac_passed = (byte[])response.getObjContents().get(1);
				if(Arrays.equals(rawHamc_2, Hmac_passed))
				{
					Envelope plaintext = (Envelope)((SealedObject)response.getObjContents().get(0)).getObject(AES_key);
					if((plaintext.getMessage()).equals("OK"))
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received == t)
						{
							t++;
							return true;
						}
						else
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
					else
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received != t)
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
				}
				t++;
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				t++;
				return false;
			}
	 }

	  public boolean createUser(String username, UserToken token)
	  {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject((Integer)t); //always put t as the first one 
				t++;//increase t to keep order 
				message.addObject(username); //Add user name string
				message.addObject(token); //Add the requester's token

				Mac mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);

				Envelope to_be_sent = new Envelope("REQ");
												
				Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
				SealedObject hmac_msg_sealed = new SealedObject(message, object_cipher);
				to_be_sent.addObject(hmac_msg_sealed);
													
				byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
				to_be_sent.addObject(rawHamc);

				output.reset();
				output.writeObject(to_be_sent);
				output.flush();
				output.reset();
			
				response = (Envelope)input.readObject();
				
				byte[] msg_combined_encrypted = convertToBytes((SealedObject)response.getObjContents().get(0));
				mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);
				byte[] rawHamc_2 = mac.doFinal(msg_combined_encrypted);
				byte[] Hmac_passed = (byte[])response.getObjContents().get(1);
				if(Arrays.equals(rawHamc_2, Hmac_passed))
				{
					Envelope plaintext = (Envelope)((SealedObject)response.getObjContents().get(0)).getObject(AES_key);
					if((plaintext.getMessage()).equals("OK"))
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received == t)
						{
							t++;
							return true;
						}
						else
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
					else
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received != t)
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
				}
				t++;
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				t++;
				return false;
			}
	 }
	 
	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
			 
				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject((Integer)t); //always put t as the first one 
				t++;//increase t to keep order 
				message.addObject(username); //Add user name string
				message.addObject(token); //Add the requester's token

				Mac mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);

				Envelope to_be_sent = new Envelope("REQ");
												
				Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
				SealedObject hmac_msg_sealed = new SealedObject(message, object_cipher);
				to_be_sent.addObject(hmac_msg_sealed);
													
				byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
				to_be_sent.addObject(rawHamc);

				output.reset();
				output.writeObject(to_be_sent);
				output.flush();
				output.reset();
			
				response = (Envelope)input.readObject();
				
				byte[] msg_combined_encrypted = convertToBytes((SealedObject)response.getObjContents().get(0));
				mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);
				byte[] rawHamc_2 = mac.doFinal(msg_combined_encrypted);
				byte[] Hmac_passed = (byte[])response.getObjContents().get(1);
				if(Arrays.equals(rawHamc_2, Hmac_passed))
				{
					Envelope plaintext = (Envelope)((SealedObject)response.getObjContents().get(0)).getObject(AES_key);
					if((plaintext.getMessage()).equals("OK"))
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received == t)
						{
							t++;
							return true;
						}
						else
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
					else
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received != t)
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
				}
				t++;
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				t++;
				return false;
			}
	 }
	 
	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject((Integer)t); //always put t as the first one 
				t++;//increase t to keep order 
				message.addObject(groupname); //Add the group name string
				message.addObject(token); //Add the requester's token

				Mac mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);

				Envelope to_be_sent = new Envelope("REQ");
												
				Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
				SealedObject hmac_msg_sealed = new SealedObject(message, object_cipher);
				to_be_sent.addObject(hmac_msg_sealed);
													
				byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
				to_be_sent.addObject(rawHamc);

				output.reset();
				output.writeObject(to_be_sent);
				output.flush();
				output.reset(); 
			
				response = (Envelope)input.readObject();
				
				byte[] msg_combined_encrypted = convertToBytes((SealedObject)response.getObjContents().get(0));
				mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);
				byte[] rawHamc_2 = mac.doFinal(msg_combined_encrypted);
				byte[] Hmac_passed = (byte[])response.getObjContents().get(1);
				if(Arrays.equals(rawHamc_2, Hmac_passed))
				{
					Envelope plaintext = (Envelope)((SealedObject)response.getObjContents().get(0)).getObject(AES_key);
					if((plaintext.getMessage()).equals("OK"))
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received == t)
						{
							t++;
							return true;
						}
						else
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
					else
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received != t)
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
				}
				t++;
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				t++;
				return false;
			}
	 }
	 
	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject((Integer)t); //always put t as the first one 
				t++;//increase t to keep order 
				message.addObject(groupname); //Add the group name string
				message.addObject(token); //Add the requester's token

				Mac mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);

				Envelope to_be_sent = new Envelope("REQ");
												
				Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
				SealedObject hmac_msg_sealed = new SealedObject(message, object_cipher);
				to_be_sent.addObject(hmac_msg_sealed);
													
				byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
				to_be_sent.addObject(rawHamc);

				output.reset();
				output.writeObject(to_be_sent);
				output.flush();
				output.reset(); 
			
				response = (Envelope)input.readObject();
				
				byte[] msg_combined_encrypted = convertToBytes((SealedObject)response.getObjContents().get(0));
				mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);
				byte[] rawHamc_2 = mac.doFinal(msg_combined_encrypted);
				byte[] Hmac_passed = (byte[])response.getObjContents().get(1);
				if(Arrays.equals(rawHamc_2, Hmac_passed))
				{
					Envelope plaintext = (Envelope)((SealedObject)response.getObjContents().get(0)).getObject(AES_key);
					if((plaintext.getMessage()).equals("OK"))
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received == t)
						{
							t++;
							return true;
						}
						else
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
					else
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received != t)
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
				}
				t++;
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				t++;
				return false;
			}
	 }
	 
	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 message.addObject((Integer)t); //always put t as the first one 
			 t++;//increase t to keep order 
			 message.addObject(group); //Add the group name string
			 message.addObject(token); //Add the requester's token

			 Mac mac = Mac.getInstance("HmacSHA256", "BC");
			 mac.init(identity_key);

			 Envelope to_be_sent = new Envelope("REQ");							
			 Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			 object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
			 SealedObject hmac_msg_sealed = new SealedObject(message, object_cipher);
			 to_be_sent.addObject(hmac_msg_sealed);
													
			 byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
			 to_be_sent.addObject(rawHamc);

			 output.reset();
			 output.writeObject(to_be_sent);
			 output.flush();
			 output.reset(); 
			
			response = (Envelope)input.readObject();
			
			byte[] msg_combined_encrypted = convertToBytes((SealedObject)response.getObjContents().get(0));
			mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(identity_key);
			byte[] rawHamc_2 = mac.doFinal(msg_combined_encrypted);
			byte[] Hmac_passed = (byte[])response.getObjContents().get(1);
			if(Arrays.equals(rawHamc_2, Hmac_passed))
			{
				Envelope plaintext = (Envelope)((SealedObject)response.getObjContents().get(0)).getObject(AES_key);
				if((plaintext.getMessage()).equals("OK"))
				{
					int t_received = (Integer)plaintext.getObjContents().get(0);
					if(t_received == t)
					{
						t++;
						return (List<String>)plaintext.getObjContents().get(1);
					}
					else
					{
						System.out.println("The message is replayed/reordered.");
					}
				}
				else
				{
					int t_received = (Integer)plaintext.getObjContents().get(0);
					if(t_received != t)
					{
						System.out.println("The message is replayed/reordered.");
					}
				}
			}
			t++;
			return null;
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				t++;
				return null;
			}
	 }
	 
	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject((Integer)t); //always put t as the first one 
			 	t++;//increase t to keep order 
			 	message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token

			 	Mac mac = Mac.getInstance("HmacSHA256", "BC");
			 	mac.init(identity_key);

			 	Envelope to_be_sent = new Envelope("REQ");
												
			 	Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			 	object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
			 	SealedObject hmac_msg_sealed = new SealedObject(message, object_cipher);
			 	to_be_sent.addObject(hmac_msg_sealed);
													
				byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
			 	to_be_sent.addObject(rawHamc);

				output.reset();
				output.writeObject(to_be_sent);
				output.flush();
				output.reset(); 
			
				response = (Envelope)input.readObject();
				
				byte[] msg_combined_encrypted = convertToBytes((SealedObject)response.getObjContents().get(0));
				mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);
				byte[] rawHamc_2 = mac.doFinal(msg_combined_encrypted);
				byte[] Hmac_passed = (byte[])response.getObjContents().get(1);
				if(Arrays.equals(rawHamc_2, Hmac_passed))
				{
					Envelope plaintext = (Envelope)((SealedObject)response.getObjContents().get(0)).getObject(AES_key);
					if((plaintext.getMessage()).equals("OK"))
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received == t)
						{
							t++;
							return true;
						}
						else
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
					else
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received != t)
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
				}
				t++;
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				t++;
				return false;
			}
	 }
	 
	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject((Integer)t); //always put t as the first one 
			 	t++;//increase t to keep order 
			 	message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token

			 	Mac mac = Mac.getInstance("HmacSHA256", "BC");
			 	mac.init(identity_key);

			 	Envelope to_be_sent = new Envelope("REQ");
												
			 	Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			 	object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
			 	SealedObject hmac_msg_sealed = new SealedObject(message, object_cipher);
			 	to_be_sent.addObject(hmac_msg_sealed);
													
				byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
			 	to_be_sent.addObject(rawHamc);

				output.reset();
				output.writeObject(to_be_sent);
				output.flush();
				output.reset(); 
			
				response = (Envelope)input.readObject();
				
				byte[] msg_combined_encrypted = convertToBytes((SealedObject)response.getObjContents().get(0));
				mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);
				byte[] rawHamc_2 = mac.doFinal(msg_combined_encrypted);
				byte[] Hmac_passed = (byte[])response.getObjContents().get(1);
				if(Arrays.equals(rawHamc_2, Hmac_passed))
				{
					Envelope plaintext = (Envelope)((SealedObject)response.getObjContents().get(0)).getObject(AES_key);
					if((plaintext.getMessage()).equals("OK"))
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received == t)
						{
							t++;
							return true;
						}
						else
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
					else
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received != t)
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
				}
				t++;
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				t++;
				return false;
			}
	 }

	 public UserToken getToken_fileOperation(String username, ArrayList<String> groups)
	 {
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;
		 		 	
			//Tell the server to return a token.
			message = new Envelope("FILEOPERATION");
			message.addObject((Integer)t); //always put t as the first one 
			t++;//increase t to keep order 
			message.addObject(username); //Add user name string
			message.addObject(groups);

			Mac mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(identity_key);

			Envelope to_be_sent = new Envelope("REQ");
												
			Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
			SealedObject hmac_msg_sealed = new SealedObject(message, object_cipher);
			to_be_sent.addObject(hmac_msg_sealed);
													
			byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
			to_be_sent.addObject(rawHamc);

			output.reset();
			output.writeObject(to_be_sent);
			output.flush();
			output.reset();
		
			//Get the response from the server
			response = (Envelope)input.readObject();
			
			byte[] msg_combined_encrypted = convertToBytes((SealedObject)response.getObjContents().get(0));
			mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(identity_key);
			byte[] rawHamc_2 = mac.doFinal(msg_combined_encrypted);
			byte[] Hmac_passed = (byte[])response.getObjContents().get(1);
			if(Arrays.equals(rawHamc_2, Hmac_passed))
			{
				Envelope plaintext = (Envelope)((SealedObject)response.getObjContents().get(0)).getObject(AES_key);
				if((plaintext.getMessage()).equals("OK"))
				{
					//If there is a token in the Envelope, return it 
					ArrayList<Object> temp = plaintext.getObjContents();
				
					if(temp != null && temp.size() == 2)
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received == t)
						{
							token = (UserToken)temp.get(1);
							t++;
							System.out.println("Returning file server keys ");
							return token;
						}
						else
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
				}
				else
				{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received != t)
						{
							System.out.println("The message is replayed/reordered.");
						}
				}
			}
			t++;
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			t++;
			return null;
		}		
	 }

	 public UserToken getToken_connectToFileServer(String username, ArrayList<String> groups, PublicKey key)
	 {
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;
		 		 	
			//Tell the server to return a token.
			message = new Envelope("CONNECT_FILE_SERVER");
			message.addObject((Integer)t); //always put t as the first one 
			t++;//increase t to keep order 
			message.addObject(username); //Add user name string
			message.addObject(groups);
			message.addObject(key);

			Mac mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(identity_key);

			Envelope to_be_sent = new Envelope("REQ");
												
			Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
			SealedObject hmac_msg_sealed = new SealedObject(message, object_cipher);
			to_be_sent.addObject(hmac_msg_sealed);
													
			byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
			to_be_sent.addObject(rawHamc);

			output.reset();
			output.writeObject(to_be_sent);
			output.flush();
			output.reset();
		
			//Get the response from the server
			response = (Envelope)input.readObject();
			
			byte[] msg_combined_encrypted = convertToBytes((SealedObject)response.getObjContents().get(0));
			mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(identity_key);
			byte[] rawHamc_2 = mac.doFinal(msg_combined_encrypted);
			byte[] Hmac_passed = (byte[])response.getObjContents().get(1);
			if(Arrays.equals(rawHamc_2, Hmac_passed))
			{
				Envelope plaintext = (Envelope)((SealedObject)response.getObjContents().get(0)).getObject(AES_key);
				if((plaintext.getMessage()).equals("OK"))
				{
					//If there is a token in the Envelope, return it 
					ArrayList<Object> temp = plaintext.getObjContents();
				
					if(temp != null && temp.size() == 2)
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received == t)
						{
							token = (UserToken)temp.get(1);
							t++;
							return token;
						}
						else
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
				}
				else
				{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received != t)
						{
							System.out.println("The message is replayed/reordered.");
						}
				}
			}
			t++;
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			t++;
			return null;
		}		
	 }

	public boolean requestUser(byte[] encryptedRequestContents) {
		Envelope req = new Envelope("CREATE-REQ");
		Envelope response = null;
		try {
			req.addObject(encryptedRequestContents);
			output.reset();
			output.writeObject(req);
			output.flush();
			output.reset();

			response = (Envelope)input.readObject();
		} catch (Exception ex) {
			System.err.println("Error in requesting user creation: " + ex);
		}
		
		if (response != null && response.getMessage().equals("OK")) { return true; }
		else { return false; }
	}

	public Hashtable<String, PublicKey> lUserRequests(UserToken token) {
		try
		{
			Envelope response = null;
			Envelope message = new Envelope("LREQS");
			message.addObject((Integer)t);
			t++;
			message.addObject(token);
			
			Mac mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(identity_key);

			Envelope to_be_sent = new Envelope("REQ");
													
			Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
									
			SealedObject hmac_msg_sealed = new SealedObject(message, object_cipher);
			to_be_sent.addObject(hmac_msg_sealed);
														
			byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
			to_be_sent.addObject(rawHamc);

			output.reset();
			output.writeObject(to_be_sent);
			output.flush();
			output.reset();

			//Get the response from the server
			response = (Envelope)input.readObject();
			
			byte[] msg_combined_encrypted = convertToBytes((SealedObject)response.getObjContents().get(0));
			mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(identity_key);
			byte[] rawHamc_2 = mac.doFinal(msg_combined_encrypted);
			byte[] Hmac_passed = (byte[])response.getObjContents().get(1);
			if(Arrays.equals(rawHamc_2, Hmac_passed))
			{
				Envelope plaintext = (Envelope)((SealedObject)response.getObjContents().get(0)).getObject(AES_key);
				if((plaintext.getMessage()).equals("OK"))
				{
					//If there is a token in the Envelope, return it 
					ArrayList<Object> temp = plaintext.getObjContents();
				
					if(temp != null && temp.size() == 2)
					{
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received == t)
						{
							Hashtable<String, PublicKey> request_table = (Hashtable<String, PublicKey>)plaintext.getObjContents().get(1);
							t++;
							return request_table;
						}
						else
						{
							System.out.println("The message is replayed/reordered.");
						}
					}
				}
				else
				{
					int t_received = (Integer)plaintext.getObjContents().get(0);
					if(t_received != t)
					{
							System.out.println("The message is replayed/reordered.");
					}
				}
			}
			t++;
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			t++;
			return null;
		}		
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
