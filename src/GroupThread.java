/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;
import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.spec.*;
import java.nio.ByteBuffer;
import java.security.spec.KeySpec;
import java.math.BigInteger;

public class GroupThread extends Thread 
{
	private final Socket socket;
	private GroupServer my_gs;
	private PublicKey pubKey;
	private PrivateKey privKey;
	private Key identity_key;
	private SecretKey AES_key;
	private ObjectInputStream input;
	private ObjectOutputStream output;
	private int t; 
	
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}
	
	public void run()
	{
		boolean proceed = true;
		Security.addProvider(new BouncyCastleProvider());
		String RSA_Method = "RSA/NONE/OAEPWithSHA256AndMGF1Padding";
		String AES_Method = "AES/CBC/PKCS5Padding";
		String userRequestsFile = "UserRequests.bin";
		
		privKey = my_gs.privKey;
		pubKey = my_gs.pubKey;

		SecretKey AES_key = null;
		identity_key = null;
	
		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			input = new ObjectInputStream(socket.getInputStream());
		    output = new ObjectOutputStream(socket.getOutputStream());
			
			Envelope first_message = (Envelope)input.readObject();
			System.out.println("receive message from client");
			Envelope response_a = null; //the response for authentication 

			boolean authOrNot = true; //did we authenticate already?
		    if(first_message.getMessage().equals("GetPubKey"))
		    {
		    	Envelope rsp = null;
		    	//load group server's public key 
				try
				{
		            rsp = new Envelope("OK");
		            rsp.addObject(pubKey);
		            authOrNot = false;
				}
				catch(Exception ex)
				{
					System.out.println("Fail to load public key" + ex);
					socket.close();
					System.out.println("Socket close");
					proceed = false;
					rsp = new Envelope("FAIL");
				}
				output.writeObject(rsp);
		    }

		    if(proceed)
		    {
				if(!authOrNot)
				{
					first_message = (Envelope)input.readObject();
					
					if(first_message.getMessage().equals("AUTH"))
					{
						if((AES_key = authenticate(first_message)) == null) 
						{
							socket.close();
							proceed = false;
							System.out.println("Auth failed, closing connection.");
						}
					}
					else if(first_message.getMessage().equals("CREATE-REQ")) 
					{
						System.out.print("beginning decryption...");
					
						ObjectInputStream reqsIn = new ObjectInputStream(new FileInputStream(userRequestsFile));
						Hashtable<String, PublicKey> requests_pubKeys = (Hashtable<String, PublicKey>)reqsIn.readObject();
						reqsIn.close();

						ObjectOutputStream reqsOut = new ObjectOutputStream(new FileOutputStream(userRequestsFile));
						byte[] encryptedReq = (byte[])first_message.getObjContents().get(0);
						byte[] encReq1 = Arrays.copyOfRange(encryptedReq, 0, encryptedReq.length/2);
						byte[] encReq2 = Arrays.copyOfRange(encryptedReq, encryptedReq.length/2, encryptedReq.length);
						Envelope resp = new Envelope("FAIL");
						//decrypt message
						try {
							Cipher ciph = Cipher.getInstance("RSA", "BC");
							ciph.init(Cipher.DECRYPT_MODE, privKey);
							byte[] plain1 = ciph.doFinal(encReq1);
							byte[] plain2 = ciph.doFinal(encReq2);
							byte[] plain = new byte[plain1.length + plain2.length];
							System.arraycopy(plain1, 0, plain, 0, plain1.length);
							System.arraycopy(plain2, 0, plain, plain1.length, plain2.length);
							ByteArrayInputStream bIn = new ByteArrayInputStream(plain);
							ObjectInputStream oIn = new ObjectInputStream(bIn);
							ArrayList<byte[]> reqContents = (ArrayList<byte[]>)oIn.readObject();
							String uname = new String(reqContents.get(0));
							PublicKey uPubKey = KeyFactory.getInstance("RSA", "BC").generatePublic(new X509EncodedKeySpec(reqContents.get(1)));
							requests_pubKeys.put(uname, uPubKey);
							reqsOut.writeObject(requests_pubKeys);
							reqsOut.close();
							resp = new Envelope("OK");
							System.out.println("done");
						} catch(Exception e) {
							System.err.println("Error in processing create user request:");
							e.printStackTrace();
						}
						System.out.print("Sending response...");
						output.reset();
						output.writeObject(resp);
						output.flush();
						output.reset();
						System.out.println("done");

						//close the connection when the create user request finished. 
						System.out.println("connection is closing from the server side");
						socket.close();	
						proceed = false; //skip the loop
					}
					else
					{
						System.out.println("connection is closing from the server side");
						socket.close();
						proceed = false; //skip the loop
					}
				}
				else
				{
					if((AES_key = authenticate(first_message)) == null) 
					{
							socket.close();
							proceed = false;
							System.out.println("Auth failed, closing connection.");
					}
				}
			}
			while(proceed)
			{
				Envelope message = (Envelope)input.readObject();
				String instruction = "";
				if(message.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					break; //end communication loop
				}
				byte[] msg_combined_encrypted = convertToBytes((SealedObject)(message.getObjContents().get(0)));
				Mac mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);
				byte[] rawHamc = mac.doFinal(msg_combined_encrypted);
				byte[] Hmac_passed = (byte[])message.getObjContents().get(1);
				Envelope plaintext = null;
				if(Arrays.equals(rawHamc, Hmac_passed))
				{
						plaintext = (Envelope)((SealedObject)message.getObjContents().get(0)).getObject(AES_key);
						int t_received = (Integer)plaintext.getObjContents().get(0);
						if(t_received == t)
						{
							instruction = plaintext.getMessage();
							t++;
						}
						else
						{
							proceed = false;
							socket.close();  //close the connection
							System.out.println("The message is replayed/reordered!");
							break;
						}
				} 
				else 
				{
					System.out.println("HMAC could not be verified!");
				}
				System.out.println("Request received: " + instruction);
				Envelope response = null;
				
				if(instruction.equals("GET"))//Client wants a token
				{
					String username = new String((String)plaintext.getObjContents().get(1)); //Get the username
					if(username == null)
					{
						response = new Envelope("FAIL");
						response.addObject((Integer)t);	
						t++;
						response.addObject(null);
					} else {
						UserToken yourToken = createToken(username); //Create a token
						yourToken.tokSign(privKey); //sign the token for the file server authentication purpose
						
						//Respond to the client. On error, the client will receive a null token
						if(yourToken != null) {
							response = new Envelope("OK");
						} else {
							response = new Envelope("FAIL");
						}
						response.addObject((Integer)t);	
					    t++;
					   	response.addObject(yourToken);    
					}

					mac = Mac.getInstance("HmacSHA256", "BC");
					mac.init(identity_key);

					Envelope to_be_sent = new Envelope("RSP");
								
					Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
					SealedObject hmac_msg_sealed = new SealedObject(response, object_cipher);
					to_be_sent.addObject(hmac_msg_sealed);
								
					byte[] rawHamc_2 = mac.doFinal(convertToBytes(hmac_msg_sealed));
					to_be_sent.addObject(rawHamc_2);
						
			   		output.writeObject(to_be_sent);
				   	output.flush();
					output.reset();
				}

				else if(instruction.equals("LREQS")) {
					response = new Envelope("FAIL");
					Token tok = (Token)plaintext.getObjContents().get(1);
					if(tok.getGroups().contains("ADMIN")) {
						ObjectInputStream reqsIn = new ObjectInputStream(new FileInputStream(userRequestsFile));
						Hashtable<String, PublicKey> requests_pubKeys = (Hashtable<String, PublicKey>)reqsIn.readObject();
						reqsIn.close();
						response = new Envelope("OK");
						response.addObject((Integer)t);
						t++;
						response.addObject(requests_pubKeys);
					}
					else
					{
						response.addObject((Integer)t);
						t++;
					}
					mac = Mac.getInstance("HmacSHA256", "BC");
					mac.init(identity_key);

					Envelope to_be_sent = new Envelope("RSP");
								
					Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
					SealedObject hmac_msg_sealed = new SealedObject(response, object_cipher);
					to_be_sent.addObject(hmac_msg_sealed);
								
					byte[] rawHamc_2 = mac.doFinal(convertToBytes(hmac_msg_sealed));
					to_be_sent.addObject(rawHamc_2);
						
			   		output.writeObject(to_be_sent);
					output.flush();
					output.reset();
				}
				else if(instruction.equals("GET_SUBSET"))//Client wants a token
				{
					String username = (String)plaintext.getObjContents().get(1); //Get the username
					ArrayList<String> subset = null;

					//@SuppressWarnings("unchecked")
					if(plaintext.getObjContents().get(2) != null) {
					    subset = new ArrayList<String>((ArrayList<String>)plaintext.getObjContents().get(2));
				    }
					if(username == null || subset == null)
					{
						response = new Envelope("FAIL");
						response.addObject((Integer)t);	
					    t++;
						response.addObject(null);
					}
					else
					{
						UserToken yourToken = createToken(username, subset); //Create a token
						yourToken.tokSign(privKey); //sign the token for the file server authentication purpose
						
						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject((Integer)t);	
					    t++;
						response.addObject(yourToken);
					}
					mac = Mac.getInstance("HmacSHA256", "BC");
					mac.init(identity_key);

					Envelope to_be_sent = new Envelope("RSP");
								
					Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
					SealedObject hmac_msg_sealed = new SealedObject(response, object_cipher);
					to_be_sent.addObject(hmac_msg_sealed);
								
					byte[] rawHamc_2 = mac.doFinal(convertToBytes(hmac_msg_sealed));
					to_be_sent.addObject(rawHamc_2);
						
			   		output.writeObject(to_be_sent);
					output.flush();
					output.reset();
				}
				else if(instruction.equals("CUSER")) //Client wants to create a user
				{
					if(plaintext.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
						response.addObject((Integer)t);	
					    t++;
					}
					else
					{
						response = new Envelope("FAIL");
						if(plaintext.getObjContents().size() == 3)
						{
							if(plaintext.getObjContents().get(1) != null) //index 0 is the username wanted to add 
							{
								if(plaintext.getObjContents().get(2) != null) //index 1 is the token from user requested
								{
									String username = (String)plaintext.getObjContents().get(1); //Extract the username
									UserToken yourToken = (UserToken)plaintext.getObjContents().get(2); //Extract the token
									if(createUser(username, yourToken))
									{
											response = new Envelope("OK"); //Success
									}
								}
							}
						}
						else if(plaintext.getObjContents().size() == 4)
						{
							if(plaintext.getObjContents().get(1) != null) //index 0 is the username wanted to add 
							{
								if(plaintext.getObjContents().get(2) != null) //index 1 is the token from user requested
								{
									if(plaintext.getObjContents().get(3) != null)//index 2 is the public key of the user to be added
									{
										String username = (String)plaintext.getObjContents().get(1); //Extract the username
										UserToken yourToken = (UserToken)plaintext.getObjContents().get(2); //Extract the token
										PublicKey to_be_added = (PublicKey)plaintext.getObjContents().get(3);//Extract the public key
										if(createUser(username, yourToken, to_be_added))
										{
											response = new Envelope("OK"); //Success
										}
									}
								}
							}
						}
						response.addObject((Integer)t);	
					   	t++;
					}
					mac = Mac.getInstance("HmacSHA256", "BC");
					mac.init(identity_key);

					Envelope to_be_sent = new Envelope("RSP");
								
					Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
					SealedObject hmac_msg_sealed = new SealedObject(response, object_cipher);
					to_be_sent.addObject(hmac_msg_sealed);
								
					byte[] rawHamc_2 = mac.doFinal(convertToBytes(hmac_msg_sealed));
					to_be_sent.addObject(rawHamc_2);
						
			   		output.writeObject(to_be_sent);
					output.flush();
					output.reset();
				}
				else if(instruction.equals("DUSER")) //Client wants to delete a user
				{
					
					if(plaintext.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
						response.addObject((Integer)t);	
					    t++;
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(plaintext.getObjContents().get(1) != null)
						{
							if(plaintext.getObjContents().get(2) != null)
							{
								String username = (String)plaintext.getObjContents().get(1); //Extract the username
								UserToken yourToken = (UserToken)plaintext.getObjContents().get(2); //Extract the token
								
								if(deleteUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
						response.addObject((Integer)t);	
					   	t++;
					}

					mac = Mac.getInstance("HmacSHA256", "BC");
					mac.init(identity_key);

					Envelope to_be_sent = new Envelope("RSP");
								
					Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
					SealedObject hmac_msg_sealed = new SealedObject(response, object_cipher);
					to_be_sent.addObject(hmac_msg_sealed);
								
					byte[] rawHamc_2 = mac.doFinal(convertToBytes(hmac_msg_sealed));
					to_be_sent.addObject(rawHamc_2);
						
			   		output.writeObject(to_be_sent);
					output.flush();
					output.reset();
				}
				else if(instruction.equals("CGROUP")) //Client wants to create a group
				{
				    if(plaintext.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
						response.addObject((Integer)t);	
					    t++;
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(plaintext.getObjContents().get(1) != null) //index 0 is the username wanted to add 
						{
							if(plaintext.getObjContents().get(2) != null) //index 1 is the token from user requested
							{
								String groupname = (String)plaintext.getObjContents().get(1); //Extract the username
								UserToken yourToken = (UserToken)plaintext.getObjContents().get(2); //Extract the token
								
								if(createGroup(groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
						response.addObject((Integer)t);	
					   	t++;
					}
		
					mac = Mac.getInstance("HmacSHA256", "BC");
					mac.init(identity_key);

					Envelope to_be_sent = new Envelope("RSP");
								
					Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
					SealedObject hmac_msg_sealed = new SealedObject(response, object_cipher);
					to_be_sent.addObject(hmac_msg_sealed);
								
					byte[] rawHamc_2 = mac.doFinal(convertToBytes(hmac_msg_sealed));
					to_be_sent.addObject(rawHamc_2);
						
			   		output.writeObject(to_be_sent);
					output.flush();
					output.reset();
				}
				else if(instruction.equals("DGROUP")) //Client wants to delete a group
				{
				    if(plaintext.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
						response.addObject((Integer)t);	
					    t++;
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(plaintext.getObjContents().get(1) != null)
						{
							if(plaintext.getObjContents().get(2) != null)
							{
								String groupname = (String)plaintext.getObjContents().get(1); //Extract the username
								UserToken yourToken = (UserToken)plaintext.getObjContents().get(2); //Extract the token
								
								if(deleteGroup(groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
									response.addObject((Integer)t);	
								}
							}
						}
						response.addObject((Integer)t);	
					    t++;
					}
					
					mac = Mac.getInstance("HmacSHA256", "BC");
					mac.init(identity_key);

					Envelope to_be_sent = new Envelope("RSP");
								
					Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
					SealedObject hmac_msg_sealed = new SealedObject(response, object_cipher);
					to_be_sent.addObject(hmac_msg_sealed);
								
					byte[] rawHamc_2 = mac.doFinal(convertToBytes(hmac_msg_sealed));
					to_be_sent.addObject(rawHamc_2);
						
			   		output.writeObject(to_be_sent);
					output.flush();
					output.reset();
				}
				else if(instruction.equals("LMEMBERS")) //Client wants a list of members in a group
				{
					response = new Envelope("FAIL");
					response.addObject((Integer)t);	
					response.addObject(null);
					
					if(!(plaintext.getObjContents().size() < 3))
					{
							
						if(plaintext.getObjContents().get(1) != null) 
						{
							if(plaintext.getObjContents().get(2) != null)
							{
								String groupname = (String)plaintext.getObjContents().get(1); //Extract the group
								UserToken yourToken = (UserToken)plaintext.getObjContents().get(2); //Extract the token
								
								List<String> returnedMember = listMembers(groupname, yourToken);

								if(returnedMember != null)
								{
									response = new Envelope("OK"); //Success
									response.addObject((Integer)t);	
									response.addObject(returnedMember);
								}
							}
						}
					}
					t++;
					mac = Mac.getInstance("HmacSHA256", "BC");
					mac.init(identity_key);

					Envelope to_be_sent = new Envelope("RSP");
								
					Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
					SealedObject hmac_msg_sealed = new SealedObject(response, object_cipher);
					to_be_sent.addObject(hmac_msg_sealed);
								
					byte[] rawHamc_2 = mac.doFinal(convertToBytes(hmac_msg_sealed));
					to_be_sent.addObject(rawHamc_2);
						
			   		output.writeObject(to_be_sent);
					output.flush();
					output.reset();
				}
				else if(instruction.equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
				    if(plaintext.getObjContents().size() < 4) //three objects in this method 
					{
						response = new Envelope("FAIL");
						response.addObject((Integer)t);	
						t++;
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(plaintext.getObjContents().get(1) != null) //index 0 is the username wanted to add 
						{
							if(plaintext.getObjContents().get(2) != null) //index 1 is the group name to be added
							{
								if(plaintext.getObjContents().get(3) != null) // index 2 is the token from user requested
								{
									String username = (String)plaintext.getObjContents().get(1); //Extract the username
									String groupname = (String)plaintext.getObjContents().get(2);
									UserToken yourToken = (UserToken)plaintext.getObjContents().get(3); //Extract the token
								
									if(addUserToGroup(username, groupname, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
						response.addObject((Integer)t);	
						t++;
					}
					mac = Mac.getInstance("HmacSHA256", "BC");
					mac.init(identity_key);

					Envelope to_be_sent = new Envelope("RSP");
								
					Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
					SealedObject hmac_msg_sealed = new SealedObject(response, object_cipher);
					to_be_sent.addObject(hmac_msg_sealed);
								
					byte[] rawHamc_2 = mac.doFinal(convertToBytes(hmac_msg_sealed));
					to_be_sent.addObject(rawHamc_2);
						
			   		output.writeObject(to_be_sent);
					output.flush();
					output.reset();
				}
				else if(instruction.equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
				    if(plaintext.getObjContents().size() < 4) //three objects in this method 
					{
						response = new Envelope("FAIL");
						response.addObject((Integer)t);	
						t++;
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(plaintext.getObjContents().get(1) != null) //index 0 is the username wanted to add 
						{
							if(plaintext.getObjContents().get(2) != null) //index 1 is the group name to be added
							{
								if(plaintext.getObjContents().get(3) != null) // index 2 is the token from user requested
								{
									String username = (String)plaintext.getObjContents().get(1); //Extract the username
									String groupname = (String)plaintext.getObjContents().get(2);
									UserToken yourToken = (UserToken)plaintext.getObjContents().get(3); //Extract the token
								
									if(deleteUserFromGroup(username, groupname, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
						response.addObject((Integer)t);	
						t++;
					}
					mac = Mac.getInstance("HmacSHA256", "BC");
					mac.init(identity_key);

					Envelope to_be_sent = new Envelope("RSP");
								
					Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
					SealedObject hmac_msg_sealed = new SealedObject(response, object_cipher);
					to_be_sent.addObject(hmac_msg_sealed);
								
					byte[] rawHamc_2 = mac.doFinal(convertToBytes(hmac_msg_sealed));
					to_be_sent.addObject(rawHamc_2);
						
			   		output.writeObject(to_be_sent);
					output.flush();
					output.reset();
				}
				else if(instruction.equals("FILEOPERATION"))//client wants to get a token to encrypt/decrypt files 
				{
					String username = (String)plaintext.getObjContents().get(1); //Get the username
					ArrayList<String> subset = null;

					//@SuppressWarnings("unchecked")
					if(plaintext.getObjContents().get(2) != null) {
						//subset should only have one element in it 
					    subset = new ArrayList<String>((ArrayList<String>)plaintext.getObjContents().get(2));
				    }
					if(username == null || subset == null || subset.size() != 1)
					{
						response = new Envelope("FAIL");
						response.addObject((Integer)t);	
					    t++;
						response.addObject(null);
					}
					else
					{
						if(my_gs.groupList.checkGroup(subset.get(0)))
						{
							if(my_gs.groupList.getFileKeys(subset.get(0)) != null)
							{
								ArrayList<SecretKey> file_keys = new ArrayList<SecretKey>(my_gs.groupList.getFileKeys(subset.get(0)));
								UserToken yourToken = createToken(username, subset, file_keys); //Create a token
								yourToken.tokSign(privKey); //sign the token for the file server authentication purpose
								
								//Respond to the client. On error, the client will receive a null token
								response = new Envelope("OK");
								response.addObject((Integer)t);	
							    t++;
								response.addObject(yourToken);
							}
							else
							{
								response = new Envelope("FAIL");
								response.addObject((Integer)t);	
							    t++;
								response.addObject(null);
							}
						}
						else
						{
							response = new Envelope("FAIL");
							response.addObject((Integer)t);	
						    t++;
							response.addObject(null);
						}
					}
					mac = Mac.getInstance("HmacSHA256", "BC");
					mac.init(identity_key);

					Envelope to_be_sent = new Envelope("RSP");
								
					Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
					SealedObject hmac_msg_sealed = new SealedObject(response, object_cipher);
					to_be_sent.addObject(hmac_msg_sealed);
								
					byte[] rawHamc_2 = mac.doFinal(convertToBytes(hmac_msg_sealed));
					to_be_sent.addObject(rawHamc_2);
						
			   		output.writeObject(to_be_sent);
					output.flush();
					output.reset();
				}
				else if(instruction.equals("CONNECT_FILE_SERVER"))
				{
					String username = (String)plaintext.getObjContents().get(1); //Get the username
					ArrayList<String> subset = null;

					//@SuppressWarnings("unchecked")
					if(plaintext.getObjContents().get(2) != null) {
						//subset should only have one element in it 
					    subset = new ArrayList<String>((ArrayList<String>)plaintext.getObjContents().get(2));
				    }
					if(username == null || subset == null || subset.size() != 1)
					{
						response = new Envelope("FAIL");
						response.addObject((Integer)t);	
					    t++;
						response.addObject(null);
					}
					else
					{
						if(plaintext.getObjContents().get(3) != null)
						{
							PublicKey filePubKey = (PublicKey)plaintext.getObjContents().get(3);
							UserToken yourToken = createToken(username, subset, filePubKey); //Create a token
							yourToken.tokSign(privKey); //sign the token for the file server authentication purpose
								
							//Respond to the client. On error, the client will receive a null token
							response = new Envelope("OK");
							response.addObject((Integer)t);	
							t++;
							response.addObject(yourToken);
						}
						else
						{
							response = new Envelope("FAIL");
							response.addObject((Integer)t);	
							t++;
							response.addObject(null);
							
						}
					}
					mac = Mac.getInstance("HmacSHA256", "BC");
					mac.init(identity_key);

					Envelope to_be_sent = new Envelope("RSP");
								
					Cipher object_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					object_cipher.init(Cipher.ENCRYPT_MODE, AES_key);
								
					SealedObject hmac_msg_sealed = new SealedObject(response, object_cipher);
					to_be_sent.addObject(hmac_msg_sealed);
								
					byte[] rawHamc_2 = mac.doFinal(convertToBytes(hmac_msg_sealed));
					to_be_sent.addObject(rawHamc_2);
						
			   		output.writeObject(to_be_sent);
					output.flush();
					output.reset();
				}
				//else
				//{
				//	response = new Envelope("FAIL"); //Server does not understand client request
				//	output.writeObject(response);
				//}
			}	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	//Method to create tokens
	private UserToken createToken(String username) 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
			return yourToken;
		}
		else
		{
			return null;
		}
	}
	
	private UserToken createToken(String username, ArrayList<String> subset) 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			for(String group : subset) {
			    if(!my_gs.userList.getUserGroups(username).contains(group)) {
			        subset.remove(subset.indexOf(group));
			    }
			}
			UserToken yourToken = new Token(my_gs.name, username, subset);
			return yourToken;
		}
		else
		{
			return null;
		}
	}

	private UserToken createToken(String username, ArrayList<String> subset, ArrayList<SecretKey> keyList)
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			for(String group : subset) {
			    if(!my_gs.userList.getUserGroups(username).contains(group)) {
			        subset.remove(subset.indexOf(group));
			    }
			}
			UserToken yourToken = new Token(my_gs.name, username, subset, keyList);
			return yourToken;
		}
		else
		{
			return null;
		}
	}

	private UserToken createToken(String username, ArrayList<String> subset, PublicKey key)
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			for(String group : subset) {
			    if(!my_gs.userList.getUserGroups(username).contains(group)) {
			        subset.remove(subset.indexOf(group));
			    }
			}
			UserToken yourToken = new Token(my_gs.name, username, subset, key);
			return yourToken;
		}
		else
		{
			return null;
		}
	}

	//Method to create a user
	private boolean createUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = new ArrayList<String>(yourToken.getGroups());
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					Hashtable<String, PublicKey> requests_pubKeys = null;
					try
					{
						ObjectInputStream reqsIn = new ObjectInputStream(new FileInputStream("UserRequests.bin"));
						requests_pubKeys = (Hashtable<String, PublicKey>)reqsIn.readObject();
						reqsIn.close();
					}
					catch(Exception ex)
					{
						System.out.println("Fail to read user request file.");
						return false;
					}
					if(requests_pubKeys != null && requests_pubKeys.size() != 0)
					{
						if(requests_pubKeys.containsKey(username))
						{
							PublicKey to_be_added = requests_pubKeys.get(username);
							boolean success =  my_gs.userList.addUser(username, to_be_added); //returns true if successful
							if(success)
							{
								//remove the pending requests
								try
								{
									requests_pubKeys.remove(username);
									ObjectOutputStream reqsOut = new ObjectOutputStream(new FileOutputStream("UserRequests.bin"));
									reqsOut.writeObject(requests_pubKeys);
									reqsOut.close();
									return true;
								}
								catch(Exception e)
								{
									System.out.println("Fail to update userRequestsFile");
									return false;
								}
							}
							return false;
						}
						else
						{
							return false;
						}
					}
					else
					{
						return false;
					}
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	//Method to create a user
	private boolean createUser(String username, UserToken yourToken, PublicKey to_be_added)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = new ArrayList<String>(yourToken.getGroups());
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					boolean success = my_gs.userList.addUser(username, to_be_added); //returns true if successful
					if(success)
					{
						//remove the pending requests
						try
						{
							ObjectInputStream reqsIn = new ObjectInputStream(new FileInputStream("UserRequests.bin"));
							Hashtable<String, PublicKey> requests_pubKeys = (Hashtable<String, PublicKey>)reqsIn.readObject();
							reqsIn.close();
							requests_pubKeys.remove(username);
							ObjectOutputStream reqsOut = new ObjectOutputStream(new FileOutputStream("UserRequests.bin"));
							reqsOut.writeObject(requests_pubKeys);
							reqsOut.close();
							return true;
						}
						catch(Exception e)
						{
							System.out.println("Fail to update userRequestsFile");
							return false;
						}
					}
					return false;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = new ArrayList<String>(yourToken.getGroups());
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();
					
					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}
					
					//Delete the user from the groups
					//If user is the owner, removeMember will automatically delete group!
					for(int index = 0; index < deleteFromGroups.size(); index++)
					{
						try
						{
							KeyGenerator key = KeyGenerator.getInstance("AES", "BC");
							key.init(256, new SecureRandom()); //128-bit AES key
							//generate a 128 key for new group 
							SecretKey file_key = key.generateKey();

							my_gs.groupList.removeMember(username, deleteFromGroups.get(index), file_key);
						}
						catch(Exception e)
						{
							System.out.println("Can't create a new key when a user is deleted");
							return false;
						}
					}
					
					//If groups are owned BY ONLY THIS USER, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();
					
					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}
					
					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//check if the user is the only owner of each group
						if(my_gs.groupList.getGroupOwners(deleteOwnedGroup.get(index)).size() == 1) {
						    //Use the delete group method. Token must be created for this action
						    deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
					    }
					}
					
					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					
					return true;	
				}
				else
				{
					return false; //User does not exist
				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	private boolean createGroup(String groupname, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			try
			{
				KeyGenerator key = KeyGenerator.getInstance("AES", "BC");
				key.init(256, new SecureRandom()); //128-bit AES key
				//generate a 128 key for new group 
				SecretKey file_key = key.generateKey();
				//128-bit AES key
		
				//Does user already exist?
				if(my_gs.groupList.checkGroup(groupname))
				{
					return false; //Group already exists
				}
				else if(my_gs.groupList.addGroup(groupname, requester, file_key)) //if group is successfully added
				{
				    //this method handles group creation with an owner
				    //also put the user as a group member
					my_gs.groupList.addMember(requester, groupname);
					my_gs.userList.addOwnership(requester, groupname);
					my_gs.userList.addGroup(requester, groupname);
					return true;

				} 
				else 
				{
					return false;
				}
			}
			catch (Exception e)
			{
				System.out.println("Fail to generate the first key for the group newly created");
				return false;
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	//delete a group
	private boolean deleteGroup(String groupname, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			//does the requested group exist?
			if(my_gs.groupList.checkGroup(groupname))
			{
				//is the requested group owned by the user?
				if(my_gs.groupList.checkOwnership(requester, groupname) && yourToken.getGroups().contains(groupname))
				{
					//loop through all users, removing the group from each one
	                for(String member: my_gs.groupList.getMembers(groupname)) {
						my_gs.userList.removeGroup(member, groupname);
					}
						
					//If groups are owned, remove references to ownership
					ArrayList<String> deleteGroupOwnership = my_gs.groupList.getGroupOwners(groupname);
					    
					for(String username : deleteGroupOwnership)
					{
						my_gs.userList.removeOwnership(username, groupname);
					}
					
					//Delete the group from the group list
					my_gs.groupList.deleteGroup(groupname);
						
					return true;	
				}
				else
				{
						return false; //requester does not own the group 
				}
			}
			else
			{
				return false; //the requested group does not exist 
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	/* Return a list of all users that are currently member of group*/
	private List<String> listMembers(String group, UserToken yourtoken)
	{
		String requester = yourtoken.getSubject();

		//Whether this user is the owner of this group?
		if(my_gs.groupList.checkOwnership(requester, group) && yourtoken.getGroups().contains(group))
		{
            ArrayList<String> members = new ArrayList<String>(my_gs.groupList.getMembers(group));//have to create a new instanation
            return members;
		}
		else
		{
			return null; //requester does own the group
		}
	}

	private boolean addUserToGroup(String user, String group, UserToken yourtoken)
	{
		String requester = yourtoken.getSubject();

		//does the user exist?
		if(my_gs.userList.checkUser(requester))
		{
			//get the list of group owned by requester
			ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
			
			if(temp.contains(group) && yourtoken.getGroups().contains(group))
			{
				if(my_gs.userList.checkUser(user))
				{
					if(my_gs.userList.getUserGroups(user).contains(group))
					{
                        return false; //the user is alredy added into that group
					}
					else if(my_gs.userList.addGroup(user, group) && my_gs.groupList.addMember(user, group))
					{                        
						return true; //add successfully
					} else {
						return false; //unsuccessful
					}
				}
				else
				{
                    return false; //this user is not the current user of group server
				}
			}
			else
			{
                return false; //user is not the owner of group
			}
		}
		else
		{
            return false; //user does not exist
		}
	}

	public boolean deleteUserFromGroup(String user, String group, UserToken yourtoken)
	{
		String requester = yourtoken.getSubject();

		//does the user exist?
		if(my_gs.userList.checkUser(requester))
		{
			//get the list of group owned by requester
			ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
			
			if(temp.contains(group) && yourtoken.getGroups().contains(group))
			{
				if(my_gs.userList.checkUser(user))
				{
					if(my_gs.userList.getUserGroups(user).contains(group))
					{
						
						try
						{
							KeyGenerator key = KeyGenerator.getInstance("AES", "BC");
							key.init(256, new SecureRandom()); //128-bit AES key
							//generate a 128 key for new group 
							SecretKey file_key = key.generateKey();

							my_gs.groupList.removeMember(user, group, file_key);
							my_gs.userList.removeGroup(user, group);
		                  	return true; //remove this successfully
						}
						catch (Exception e)
						{
							System.out.println("Can't create a new key when a user is deleted from the group.");
							return false;
						}
					}
					else
					{
						return false; //the user does not belong to that group
					}
				}
				else
				{
					return false; //this user is not the current user of group server
				}
			}
			else
			{
				return false; //user is not the owner of group
			}
		}
		else
		{
			return false; //user does not exist 
		}
	}

	private SecretKey authenticate(Envelope challenge) {
		SecretKey AESKey = null;
		Cipher cipher = null;
		PublicKey userKey = null;
		byte[] rand;
		KeyGenerator keyGen = null;
		KeyFactory kf = null;
		
		if (challenge == null || !challenge.getMessage().equals("AUTH")) 
		{
			return null;
		}
			
		//Stage1 -- handle receiving initial auth request
		try 
		{
			cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.DECRYPT_MODE, privKey);
			ArrayList<Object> temp = challenge.getObjContents();
			byte[] p_byte = cipher.doFinal((byte[])temp.get(0));
			byte[] g_byte = cipher.doFinal((byte[])temp.get(1));
			byte[] user_DHPub = (byte[])temp.get(2);
			byte[] sigTobeVerify = (byte[])temp.get(3);
			String username = (String)temp.get(4);
			//retrieve user's public key 
			
			if(!my_gs.userList.checkUser(username))
			{
				System.out.println("Can't find user.");
				return null;
			}
			userKey = my_gs.userList.getUserPublicKey(username);

			//verify signature. 
			Signature sig = Signature.getInstance("RSA", "BC");
			sig.initVerify(userKey);
	    	//update decrypted data to be verified and verify the data
	    	sig.update(user_DHPub);
	    	boolean verified1 = sig.verify(sigTobeVerify);

	    	if(verified1)
	    	{
	    		
		    	BigInteger p = new BigInteger(1, p_byte);
		    	BigInteger g = new BigInteger(1, g_byte);
		    	
	    		//retrieve user's DH public key
	    		kf = KeyFactory.getInstance("DH", "BC");
				X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(user_DHPub);
           		PublicKey userDHPublicKey = kf.generatePublic(x509Spec);

	    		//generate DH key pairs. 
				KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "BC");

			    DHParameterSpec param = new DHParameterSpec(p, g);
			    kpg.initialize(param);

			    KeyPair kp = kpg.generateKeyPair();

			    PrivateKey dhPrivate = kp.getPrivate();
			    PublicKey dhPublic = kp.getPublic();

			    KeyAgreement ka = KeyAgreement.getInstance("DH");
			    ka.init(dhPrivate);
			    ka.doPhase(userDHPublicKey, true);
			    AESKey = ka.generateSecret("AES");

			   	byte[] dhPublic_bytes = dhPublic.getEncoded();
			    //we need to sign this value. 

			    //generate signature
				sig = Signature.getInstance("RSA", "BC");
				sig.initSign(privKey, new SecureRandom());
				//update encrypted data to be signed and sign the data 
				sig.update(dhPublic_bytes);
				byte[] sigBytes = sig.sign();

				byte[] sigBytesHmac = sig.sign();
				Envelope response = new Envelope("AUTH");
				response.addObject(dhPublic_bytes);
				response.addObject(sigBytes);
				output.writeObject(response);
	    	}
			
		} 
		catch (Exception ex) 
		{
			System.err.println("Err in handling auth request part 1: ");
			ex.printStackTrace();
			return null;
		}
		
		try
		{
			Envelope identity_request = (Envelope)((SealedObject)input.readObject()).getObject(AESKey);
			if(identity_request != null && identity_request.getMessage().equals("IDENTITY"))
			{
				//generate a 256-bit key for identity check in HMAC 
		        KeyGenerator key = KeyGenerator.getInstance("HmacSHA256", "BC");
		        key.init(256, new SecureRandom());
		        identity_key = key.generateKey();

				Random randomGenerator = new Random();
				t = randomGenerator.nextInt(2147483647/2);
				//encrypt the response by AES_key from now on
				Envelope response = new Envelope("OK");

				Mac mac = Mac.getInstance("HmacSHA256", "BC");
				mac.init(identity_key);

				Envelope to_be_sent = new Envelope("OK");
				to_be_sent.addObject((Integer)t);
				t++;//increase t to keep order 
									
				SealedObject hmac_msg_sealed = to_be_sent.encrypted(AESKey);
				response.addObject(hmac_msg_sealed);
									
				byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
				response.addObject(rawHamc); //add first object into array 

				Envelope key_env = new Envelope("INDENTITYKEY");
				key_env.addObject(identity_key);
				response.addObject(key_env.encrypted(AESKey));
							
				output.writeObject(response);
				output.flush();
				output.reset();
			}
			else
			{
				return null;
			}
		}
		catch (Exception ex) 
		{
			System.err.println("Err in handling sending identity key: ");
			ex.printStackTrace();
			return null;
		}
		System.out.println("Authentication complete, success!");
		return AESKey; //auth steps complete	
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
