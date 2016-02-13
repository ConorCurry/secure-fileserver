/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;

public class GroupThread extends Thread 
{
	private final Socket socket;
	private GroupServer my_gs;
	
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}
	
	public void run()
	{
		boolean proceed = true;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;
				
				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					if(username == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{
						UserToken yourToken = createToken(username); //Create a token
						
						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject(yourToken);
						output.writeObject(response);
					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
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
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(createUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
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
				    /* TODO:  Write this handler */
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
				    /* TODO:  Write this handler */
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
								
								List<String> returnedMember = new List<String>(listMembers(groupname, yourToken));

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
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					output.writeObject(response);
				}
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
	
	
	//Method to create a user
	private boolean createUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
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
					my_gs.userList.addUser(username);
					return true;
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
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
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
					
					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();
					
					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}
					
					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
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

	/* Return a list of all users that are currently member of group*/
	private List<String> listMembers(String group, UserToken yourtoken)
	{
		String requester = yourtoken.getSubject();

		//does the user exist?
		if(my_gs.userList.checkUser(requester))
		{
			//get the list of group owned by requester
			ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
			
			if(temp.contains(group))
			{
				
				//requester is the owner of group

				List<String> groupMember = new ArrayList<String>();
				
				//loop all the users, and check whether they belongs to this group
				Enumeration e = my_gs.userList.getAllUsers();
				while(e.hasMoreElements())
				{
					String temp_user = (String)e.nextElement();
					//check whether this user has the group
					if(my_gs.userList.getUserGroups(temp_user).contains(group))
					{
							groupMember.add(temp_user);
					}
				}
				
				return groupMember;
			}
			else
			{
				return null; //user does not own this group
			}
		}
		else
		{
			return null; //requester does not exist 
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
			
			if(temp.contains(group))
			{
				if(my_gs.userList.checkUser(user))
				{
					if(my_gs.userList.getUserGroups(user).contains(group))
					{
						return false; //the user is alredy added into that group
					}
					else
					{
						my_gs.userList.addGroup(user, group);
						return true; //add successfully
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
			
			if(temp.contains(group))
			{
				if(my_gs.userList.checkUser(user))
				{
					if(my_gs.userList.getUserGroups(user).contains(group))
					{
						my_gs.userList.removeGroup(user, group);
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