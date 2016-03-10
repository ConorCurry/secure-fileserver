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

public class GroupThread extends Thread 
{
	private final Socket socket;
	private GroupServer my_gs;
	private PublicKey pubKey;
	private PrivateKey privKey;
	
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}
	
	public void run()
	{
		boolean proceed = true;
		Security.addProvider(new BouncyCastleProvider());
		KeyPair serverKeyPair = my_gs.userList.getServerKeyPair();
		pubKey = serverKeyPair.getPublic();
		privKey = serverKeyPair.getPrivate();

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			SealedObject message_sealed = (SealedObject)input.readObject();
			Cipher scipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			scipher.init(Cipher.DECRYPT_MODE, privKey);
			Envelope plain_message = (Envelope)message_sealed.getObject(scipher);
			Envelope response_a = null;
				
			ArrayList<Object> temp = plain_message.getObjContents();
			SecretKey AES_key = null; //store shared sceret key later. 
			byte[] rndBytes = null;
			if(temp != null && temp.size() == 4)
			{
				//decrypt the sealed object with server's private key 
				Cipher dec = Cipher.getInstance("RSA", "BC");
				dec.init(Cipher.DECRYPT_MODE, privKey);
				
				String username = (String)temp.get(0);
				PublicKey usrPubKey = my_gs.userList.getUserPublicKey(username);
				//if the user exists 
				if(usrPubKey != null)
				{
					Signature sig = Signature.getInstance("RSA", "BC");
					sig.initVerify(usrPubKey);
			    	//update original data to be verified and verify the data
			    	sig.update((byte[])temp.get(2));
			    	byte[] to_be_verified = (byte[])temp.get(3);
			    	boolean verified = sig.verify(to_be_verified);
					//if matches, decrypts to get the AES key, generate a new number and encrypt that with user's public key 
			    	if(verified)
			    	{

							response_a = new Envelope("OK");
							Cipher rcipher = Cipher.getInstance("RSA", "BC");
							rcipher.init(Cipher.DECRYPT_MODE, privKey);
				    		byte[] userGeneratedNumber = rcipher.doFinal((byte[])temp.get(1));
				    		response_a.addObject(userGeneratedNumber);

				    		//get the AES key transmitted 
				    		rcipher = Cipher.getInstance("RSA", "BC");
							rcipher.init(Cipher.DECRYPT_MODE, privKey);
							byte[] encrypted_AES = (byte[])temp.get(2);
				    		AES_key = new SecretKeySpec(encrypted_AES, 0, encrypted_AES.length, "AES");
							
							SecureRandom sr = new SecureRandom();
							rndBytes = new byte[8];
							sr.nextBytes(rndBytes);
					 		Cipher cipher = Cipher.getInstance("RSA", "BC");
					 		cipher.init(Cipher.ENCRYPT_MODE, usrPubKey);
					 		response_a.addObject(cipher.doFinal(rndBytes));
					}
					else
					{
						response_a = new Envelope("FAIL");
					}
				output.writeObject(response_a.encrypted(usrPubKey));
				output.flush();
				output.reset();
				}
				else
				{
					response_a = new Envelope("FAIL");
				}
			}
			else
			{
				//what if the user does not existed in the file yet. How to fix it?
				//response = new Envelope("FAIL");
				//output.writeObject(response);
				//output.flush();
				//output.reset();
			}
			
			SealedObject message_sealed_new = (SealedObject)input.readObject();
			Cipher sdcipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			sdcipher.init(Cipher.DECRYPT_MODE, AES_key);
			Envelope plain_message_v = (Envelope)message_sealed_new.getObject(sdcipher);
			Envelope response_v = null;
			byte[] to_be_verified =(byte[]) (plain_message_v).getObjContents().get(0);
			if(Arrays.equals(to_be_verified, rndBytes))
			{
				response_v = new Envelope("OK");
			}
			else
			{
				response_v = new Envelope("FAIL");
			}
			response_v.encrypted(AES_key);
			output.writeObject(response_v);
			output.flush();
			output.reset();


			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response = null;
				
				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = new String((String)message.getObjContents().get(0)); //Get the username
					if(username == null)
					{
						response = new Envelope("FAIL");
						
						response.addObject(null);
					} else {
						UserToken yourToken = createToken(username); //Create a token
						
						//Respond to the client. On error, the client will receive a null token
						if(yourToken != null) {
							response = new Envelope("OK");
						} else {
							response = new Envelope("FAIL");
						}
					   	response.addObject(yourToken);
					}
			   		output.writeObject(response);
				   	output.flush();
					output.reset();
				}
				if(message.getMessage().equals("GET_SUBSET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					ArrayList<String> subset = null;

					//@SuppressWarnings("unchecked")
					if(message.getObjContents().get(1) != null) {
					    subset = new ArrayList<String>((ArrayList<String>)message.getObjContents().get(1));
				    }
					if(username == null || subset == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
					}
					else
					{
						UserToken yourToken = createToken(username, subset); //Create a token
						
						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject(yourToken);
					}
					output.writeObject(response);
					output.flush();
					output.reset();
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null) //index 0 is the username wanted to add 
						{
							if(message.getObjContents().get(1) != null) //index 1 is the token from user requested
							{
								if(message.getObjContents().get(2) != null)//index 2 is the public key of the user to be added
								{
									String username = (String)message.getObjContents().get(0); //Extract the username
									UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
									PublicKey to_be_added = (PublicKey)message.getObjContents().get(2);//Extract the public key
									if(createUser(username, yourToken, to_be_added))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
					}
		
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(deleteUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
				    if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null) //index 0 is the username wanted to add 
						{
							if(message.getObjContents().get(1) != null) //index 1 is the token from user requested
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(createGroup(groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
		
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
				    if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(deleteGroup(groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
					response = new Envelope("FAIL");
					response.addObject(null);
					
					if(!(message.getObjContents().size() < 2))
					{
							
						if(message.getObjContents().get(0) != null) 
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the group
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								List<String> returnedMember = listMembers(groupname, yourToken);

								if(returnedMember != null)
								{
									response = new Envelope("OK"); //Success
									response.addObject(returnedMember);
								}
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
				    if(message.getObjContents().size() < 3) //three objects in this method 
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null) //index 0 is the username wanted to add 
						{
							if(message.getObjContents().get(1) != null) //index 1 is the group name to be added
							{
								if(message.getObjContents().get(2) != null) // index 2 is the token from user requested
								{
									String username = (String)message.getObjContents().get(0); //Extract the username
									String groupname = (String)message.getObjContents().get(1);
									UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token
								
									if(addUserToGroup(username, groupname, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
				    if(message.getObjContents().size() < 3) //three objects in this method 
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null) //index 0 is the username wanted to add 
						{
							if(message.getObjContents().get(1) != null) //index 1 is the group name to be added
							{
								if(message.getObjContents().get(2) != null) // index 2 is the token from user requested
								{
									String username = (String)message.getObjContents().get(0); //Extract the username
									String groupname = (String)message.getObjContents().get(1);
									UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token
								
									if(deleteUserFromGroup(username, groupname, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				//else
				//{
				//	response = new Envelope("FAIL"); //Server does not understand client request
				//	output.writeObject(response);
				//}
			}while(proceed);	
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
	//Method to create a user
	private boolean createUser(String username, UserToken yourToken, PublicKey to_be_added)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = new ArrayList<>(yourToken.getGroups());
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
					return my_gs.userList.addUser(username, to_be_added); //returns true if successful
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
			ArrayList<String> temp = new ArrayList<>(yourToken.getGroups());
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
						my_gs.groupList.removeMember(username, deleteFromGroups.get(index));
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
			//Does user already exist?
			if(my_gs.groupList.checkGroup(groupname))
			{
				return false; //Group already exists
			}
			else if(my_gs.groupList.addGroup(groupname, requester)) //if group is successfully added
			{
			    //this method handles group creation with an owner
			    //also put the user as a group member
				my_gs.groupList.addMember(requester, groupname);
				my_gs.userList.addOwnership(requester, groupname);
				my_gs.userList.addGroup(requester, groupname);
				return true;

			} else {
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
						my_gs.userList.removeGroup(user, group);
                        my_gs.groupList.removeMember(user, group);
						return true; //remove this successfully
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
}
