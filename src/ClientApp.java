import java.io.*;
import java.util.*;
import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;

public class ClientApp
{
    private static GroupClient groupClient;
    private static FileClient fileClient;
    private static Scanner input;
    private static UserToken masterToken;
    private static UserToken FCToken; //used to communicate with file server
    private static UserToken EDToken; //used to encrypt/decrypt file locally 
    private static int choice;
    private static String username;
    private static String gs_name, fs_name;
    private static int fs_port, gs_port;
    private static UserToken token;
    private static SecretKey AES_key;
    private static final int GS_PORT = 8765;
    private static final int FS_PORT = 4321;
    private static final String RSA_Method = "RSA/NONE/OAEPWithSHA256AndMGF1Padding";
    private static final String AES_Method = "AES/CBC/PKCS5Padding";
    private static PublicKey pubKey = null;
    private static PrivateKey privKey = null;
    private static boolean fs_authentication = false;
    
    public static void main(String[] args) throws Exception
    {
        //create a new group client and file client
        groupClient = new GroupClient();
        fileClient = new FileClient();
        input = new Scanner(System.in);
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("------------Welcome to CS1653 Group-Based File Sharing application------------\n");
        do {
            System.out.print("Please enter the group server name: ");
            gs_name = input.nextLine();
            System.out.print("Please enter the port number you would like to connect on (0 for default): ");
            gs_port = input.nextInt();
            input.nextLine();
            groupClient = new GroupClient();
            if(gs_port == 0)
            {
                gs_port = GS_PORT;
            }
        } while(!groupClient.connect(gs_name, gs_port));
		System.out.print("Request a new user account? (y/n): ");
		boolean requestNew = false;
		if (input.nextLine().equalsIgnoreCase("y")) {
			try {
				if(!requestNewUser())
                {
                    System.out.println("Can't create a new account");
                    System.out.println("Exiting the application-----------------------------------------------------");
                    groupClient.disconnect();
                    System.exit(-1);
                }
			} 
            catch(Exception ex) 
            {
				System.err.print("Error in requesting new user!");
				ex.printStackTrace();
                System.out.println("Exiting the application-----------------------------------------------------");
                groupClient.disconnect();
                 System.exit(-1);
			}
		}
        do {
            System.out.print("Please enter your username to log in: ");
            username = input.nextLine();
            
            //read the key pair file to see whether the user exists already.
            FileInputStream uPubis = new FileInputStream("UserPublicKeys.bin");
            ObjectInputStream userPubKeysStream = new ObjectInputStream(uPubis);
            Hashtable<String, PublicKey> user_publicKeys = (Hashtable<String, PublicKey>)userPubKeysStream.readObject();
            uPubis.close();
            userPubKeysStream.close();

            boolean existed = false;
            //if not, forced to quit to create a new account 
            if(!user_publicKeys.containsKey(username))
            {
                System.out.println("Sorry, you are not a user yet. You need to create your account first. Exiting the application-----");
                groupClient.disconnect();
                System.exit(-1);
            }
            else
            {
                existed = true;
                try
                {
                    //read from the existed file 
                    pubKey = user_publicKeys.get(username);
                    System.out.print("Please enter your password: ");
                    String user_password = input.nextLine();

                    //hash the user's password and make it to be the secret key to encrypt the private keys 
                    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                    messageDigest.update(user_password.getBytes());
                    byte[] hashedPassword = messageDigest.digest();

                    FileInputStream uPrivis = new FileInputStream("UserPrivateKeys.bin");
                    ObjectInputStream userPrivKeysStream = new ObjectInputStream(uPrivis);
                    Hashtable<String, ArrayList<byte[]>> user_privKeys = (Hashtable<String, ArrayList<byte[]>>)userPrivKeysStream.readObject();
                    uPrivis.close();
                    userPrivKeysStream.close();

                    byte[] key_data = user_privKeys.get(username).get(0);
                    byte[] salt = user_privKeys.get(username).get(1);

                    IvParameterSpec user_ivSpec = new IvParameterSpec(salt);
                    //decrypt the one read from the file to get the server's private key 
                    Cipher cipher_privKey = Cipher.getInstance(AES_Method, "BC");
                    //create a shared key with the user's hashed password 
                    SecretKey skey = new SecretKeySpec(hashedPassword, "AES");
                    cipher_privKey.init(Cipher.DECRYPT_MODE, skey, user_ivSpec);
                    byte[] decrypted_data = cipher_privKey.doFinal(key_data);
                    
                    KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
                    privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decrypted_data));
                }
                catch(Exception ex)
                {
                    System.out.println("Fail to fetch your private key. Please re-log in and try again.");
                    System.out.println("Exiting the application----------------------------------------");
                    System.exit(-1);
                }
            }
            boolean verified = false;
            boolean getKey = true;
            String ct = "";
            if(existed)
            {
                //authenticate process to check whether the authentication succeeds.
                 PublicKey gsPubKey = null;
            
                 //look into file server's public key
                 ArrayList<PublicKey> gs_pubKeys = null;
                 try
                 {
                    FileInputStream fis = new FileInputStream("GSPublicKey_client.bin");
                    ObjectInputStream fileStream = new ObjectInputStream(fis);
                    gs_pubKeys = (ArrayList<PublicKey>)fileStream.readObject();
                    fileStream.close();
                    fis.close();
                    if(gs_pubKeys != null && gs_pubKeys.size() == 1)
                    {
                        //go to group server to request token to connect to the file server 
                        gsPubKey = gs_pubKeys.get(0);
                        if(gsPubKey != null)
                        {
                            getKey = false;
                            ct = "y";
                        }
                    }
                }
                catch(Exception e)
                {
                    //create a file contains file server public keys
                    //request public key 
                    //do nothing here 
                }
                //if we need to get a key from group server
                if(getKey)
                {
                    System.out.println("Getting key from group server");
                    gsPubKey = groupClient.getGSkey();
                    if(gsPubKey == null)
                    {
                        System.out.println("Fail to get Group Server's publc key.");
                    }
                    else
                    {
                        gs_pubKeys = new ArrayList<PublicKey>();

                        gs_pubKeys.add(gsPubKey);
                        //write server's public key to a file 
                        try
                        {
                            ObjectOutputStream sPubKOutStream = new ObjectOutputStream(new FileOutputStream("GSPublicKey_client.bin"));
                            sPubKOutStream.writeObject(gs_pubKeys);
                            sPubKOutStream.close();
                             //print public key out for user to verify 
                            System.out.println("RSA Key is: " + DatatypeConverter.printBase64Binary(gsPubKey.getEncoded()));
                            System.out.print("Do you want to continue? y/n: ");
                            ct = input.nextLine();
                        }
                        catch(Exception e)
                        {
                            System.out.println("Fail to write it back");
                        }
                    }
                }
                if(ct.equalsIgnoreCase("y"))
                { 
                   verified = groupClient.authenticate(username, privKey, gsPubKey);
                }
            }
            //if the authentication succeeds, then the user can use the AES key to acquire token 
            if(verified)
            {
                masterToken = groupClient.getToken(username); //get a token for this user
                token = masterToken;
                if(masterToken == null)
                {
                    System.out.print("Sorry, you do not belong to this group server. Try again? (y/n): ");
                    String response = input.nextLine();
                    if(!response.equalsIgnoreCase("y")){
                        groupClient.disconnect();
                        input.close();
                        System.exit(0);
                    }
                }
            }
            else
            {
               //authentication fails, users may try again or be logged out 
                System.out.print("Sorry, the authentication fails. You're forced to quit ");
                groupClient.disconnect();
                input.close();
                System.exit(0);
            }
        }while(masterToken == null);
        
        System.out.printf("Welcome %s!\n", username);
		
        changeGroups();
        while(true) {
            printGroupMenu();
        }
    }
    //public
    
    public static void printGroupMenu()
    {
        
        //retake tokens each time in case changes made by others.
        while(true){
            System.out.println("\nMain Menu: ");
            System.out.println("------------Please choose the number of what you want to do from the following options-------\n");
            System.out.println("0. Disconnect from the server and exit the application");
            System.out.println("1. Modify fileserver connection");
            System.out.println("2. Create User");
            System.out.println("3. Delete User");
            System.out.println("4. Create Group");
            System.out.println("5. Delete Group");
            System.out.println("6. Add User To Group");
            System.out.println("7. Delete User From Group");
            System.out.println("8. List members of a group");
            System.out.println("9. List the groups you belong to");
            System.out.println("10. Change the group you would like to work on");
            if(fileClient.isConnected() && fs_authentication) {
                System.out.println("11. Delete file");
                System.out.println("12. Download file");
                System.out.println("13. Upload file");
                System.out.println("14. List all accessible files");
            }
			if(token.getGroups().contains("ADMIN")) {
				System.out.println("15: List & Approve Account Requests");
			}
            System.out.print("\nPlease enter your choice: ");
            
            //check whether the choice is valid
            checkIdentity();
            try
            {
                choice = input.nextInt();
				input.nextLine();
            }
            catch(Exception e)
            {
                System.out.println("Sorry, Your choice is not valid, please enter a valid number.");
                continue;
            }
            if(choice < 0 || choice > 15)
            {
                System.out.println("Sorry, Your choice is not valid, please enter a valid number.");
            }
            else break;
        }
        //input.nextLine();
        masterToken = groupClient.getToken(username); //check whether this user does exist or not 
        if(masterToken != null)
        {
            switch(choice){
                case 0:
                    end();
                    break;
                case 1:
                    connectFileserver();
                    break;
                case 2:
                        cuser();
                    break;
                case 3:
                    duser();
                    break;
                case 4:
                    cgroup();
                    break;
                case 5:
                    dgroup();
                    break;
                case 6:
                    addUser();
                    break;
                case 7:
                    removeUser();
                    break;
                case 8:
                    listAll();
                    break;
                case 9:
                    printGroups();
                    break;
                case 10:
                    changeGroups();
                    break;
                case 11:
                    delFile();
                    break;
                case 12:
                    downloadFile();
                    break;
                case 13:
                    uploadFile();
                    break;
                case 14:
                    listFiles();
                    break;
			    case 15:
					approveRequests();
					break;
                default:
                    end();
                    break;
			}
		} else {
                System.out.println("Sorry, you're deleted by ADMIN. Forced to log out");
                end();
		}
	}
        
    public static void cuser()
    {
        System.out.print("You have chose to create user. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
			System.out.println("Disallowed characters: '&' and  ','");
            System.out.print("Please Enter the Username you would like to create: ");
            String createdUserName = input.nextLine();
            
            if(groupClient.createUser(createdUserName, token))
                    System.out.println("Congratulations! You have created user " + createdUserName + " successfully!");
            else
                    System.out.println("Sorry. You fail to create this user. Please try other options.");
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void duser()
    {
        System.out.print("You have chose to delete user. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
            System.out.print("Please Enter the Username you would like to delete: ");
            String deletedUserName = input.nextLine();
            if(groupClient.deleteUser(deletedUserName, token))
            {
                System.out.println("Congratulations! You have deleted user " + deletedUserName + " successfully!");
                
                try
                {
                    //read the key pair file to see whether the user exists already.
                    FileInputStream uPubis = new FileInputStream("UserPublicKeys.bin");
                    ObjectInputStream userPubKeysStream = new ObjectInputStream(uPubis);
                    Hashtable<String, PublicKey> user_publicKeys = (Hashtable<String, PublicKey>)userPubKeysStream.readObject();
                    uPubis.close();
                    userPubKeysStream.close();
                    user_publicKeys.remove(deletedUserName);

                    //write the updated table back to the file 
                    FileOutputStream uPubos = new FileOutputStream("UserPublicKeys.bin");
                    ObjectOutputStream uPubKOutStream = new ObjectOutputStream(uPubos);
                    uPubKOutStream.writeObject(user_publicKeys);
                    uPubos.close();
                    uPubKOutStream.close();

                    //also delete the user information saved on the file? 
                    FileInputStream uPrivis = new FileInputStream("UserPrivateKeys.bin");
                    ObjectInputStream userPrivKeysStream = new ObjectInputStream(uPrivis);
                    Hashtable<String, ArrayList<byte[]>> user_privKeys = (Hashtable<String, ArrayList<byte[]>>)userPrivKeysStream.readObject();
                    uPrivis.close();
                    userPrivKeysStream.close();
                    user_privKeys.remove(deletedUserName);

                    //write the updated table back to the file 
                    FileOutputStream uPrivos = new FileOutputStream("UserPrivateKeys.bin");
                    ObjectOutputStream uPrivKOutStream = new ObjectOutputStream(uPrivos);
                    uPrivKOutStream.writeObject(user_privKeys);
                    uPrivos.close();
                    uPrivKOutStream.close();
                }
                catch(Exception exn)
                {
                    System.out.println("Updating keys after removing a user fails." + exn);
                }
            }
            else
                System.out.println("Sorry. You fail to delete this user. Please try other options.");
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void cgroup()
    {
        System.out.print("You've chosen to create a new group. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
			System.out.println("Disallowed characters: '&' and  ','");
            String groupName;
            //make sure the group name is not empty 
            do {
                System.out.print("Please Enter the group name you would like to create: ");
                groupName = input.nextLine();
            } while(groupName.equals(""));

            if(groupClient.createGroup(groupName, token))
                System.out.println("Congratulations! You have created the new group " + groupName + " successfully!");
            else
                System.out.println("Sorry. You fail to create this group. Please try other options.");
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void dgroup()
    {
        System.out.print("You've chosen to delete a group. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
            boolean stayinGroups = groupsCheck();
            if(stayinGroups)
            {
                String groupName = selectGroup();
                if(!groupName.equals(""))
                {
                    if(groupClient.deleteGroup(groupName, token))
                    {
                          System.out.println("Congratulations! You have deleted the group " + groupName + " successfully!");
                          //update token. 
                          ArrayList<String> groups = new ArrayList <String>(token.getGroups());
                          if(groups.size() == 1 && groups.get(0).equals(groupName))
                          {
                             //you only have one group on the file, but you delete that.
                             System.out.println("You delete the group you're working on. You have to switch to other working groups.");
                             changeGroups();//select the groups and update the token 
                          }
                          else
                          {
							 groups.remove(groups.indexOf(groupName));
                             token = groupClient.getToken(username, groups);
                             System.out.println("successfully updated token!");
                          }
                    }
                    else
                      System.out.println("Sorry. You fail to delete this group. Please try other options.");
                }
			}
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void addUser()
    {
        System.out.print("You have chose to add a user to a group. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
            System.out.print("Please Enter the Username to be added: ");
            String userName = input.nextLine();
            boolean stayinGroups = groupsCheck();
            if(stayinGroups)
            {
                String groupName = selectGroup();
                if(!groupName.equals(""))
                {
                    if(groupClient.addUserToGroup(userName, groupName, token)) 
                    {
                        System.out.println("Congratulations! You have added the user " + userName +" to the group " + groupName + " successfully!");
			        }
                    else 
                    {
				        System.out.println("Sorry. You fail to add this user to the group. Please try other options.");
                    }
                }
			}
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void removeUser()
    {
        System.out.print("You've chosen to delete a user from a group. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
            System.out.print("Please Enter the Username to be deleted: ");
            String userName = input.nextLine();
            boolean stayinGroups = groupsCheck();
            if(stayinGroups)
            {
                String groupName = selectGroup();
                if(!groupName.equals(""))
                {
                    if(groupClient.deleteUserFromGroup(userName, groupName, token)) 
                    {
                            System.out.println("\nCongratulations! You have deleted the user " + userName +" from the group " + groupName + " successfully!");
        			} 
                    else 
                    {
        				System.out.println("\nSorry. You fail to delete this user from the group. Please try other options.");
                    }
                }
			}
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void listAll()
    {
        System.out.print("You have chose to list all the members of the group. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
            System.out.println();
            boolean stayinGroups = groupsCheck();
            if(stayinGroups)
            {
                String groupName = selectGroup();
                if(!groupName.equals(""))
                {
                    List<String> members = new ArrayList<String>(groupClient.listMembers(groupName, token));
                    if(members != null && !members.isEmpty())
                    {
                        System.out.println("\nCongratulations! You have fetched all the members from the group " + groupName + " successfully!");
                        System.out.println("Start to list");
                        members = new ArrayList<String>(groupClient.listMembers(groupName, token));
                        for(int i = 0; i < members.size(); i++)
                        {
                            System.out.println(""+ (i+1) + ". " + members.get(i));
                        }
                    }
                    else 
                    {
                        System.out.println("Sorry. You fail to list members of this group. Please try other options.");
                    }
                } 
            }
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void connectFileserver() {
        System.out.print("You've chosen to modify your fileserver connection. Press 1 to continue, or another number to return to the menu. ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1) {
            System.out.print("Please enter the file server name: ");
            fs_name = input.nextLine();
            System.out.print("Please enter the port number you would like to connect on (0 for default): ");
            fs_port = input.nextInt();
            input.nextLine();
            boolean getKey = true;
            String ct = "";
            
            if(fs_port == 0)
            {
                fs_port = FS_PORT;
            }

            if(!fileClient.connect(fs_name, fs_port)) {
                        fs_name = null;
                        fs_port = 0;
            }

            PublicKey fsPubKey = null;
            
            //look into file server's public key
            Hashtable<String, PublicKey> fs_pubKeys = null;
            try
            {
                FileInputStream fis = new FileInputStream("FSPublicKey_client.bin");
                ObjectInputStream fileStream = new ObjectInputStream(fis);
                fs_pubKeys = (Hashtable<String, PublicKey>)fileStream.readObject();
                if(fs_pubKeys.containsKey(fs_name + fs_port))
                {
                    //go to group server to request token to connect to the file server 
                    fsPubKey = fs_pubKeys.get(fs_name + fs_port);
                    if(fsPubKey != null)
                    {
                        getKey = false;
                        ct = "y";
                    }
                }
            }
            catch(Exception e)
            {
                //create a file contains file server public keys
                //request public key 
                //do nothing here 
            }

            if(getKey)
            {
                fsPubKey = fileClient.getFSkey();
                if(fsPubKey == null)
                {
                    System.out.println("Fail to get File Server's publc key.");
                }
                else
                {
                    if(fs_pubKeys == null)
                        fs_pubKeys = new Hashtable<String, PublicKey>();

                    fs_pubKeys.put(fs_name + fs_port, fsPubKey);
                    //write server's public key to a file 
                    try
                    {
                        ObjectOutputStream sPubKOutStream = new ObjectOutputStream(new FileOutputStream("FSPublicKey_client.bin"));
                        sPubKOutStream.writeObject(fs_pubKeys);
                        sPubKOutStream.close();
                         //print public key out for user to verify 
                        System.out.println("RSA Key is: " + DatatypeConverter.printBase64Binary(fsPubKey.getEncoded()));
                        System.out.print("Do you want to continue? y/n: ");
                        ct = input.nextLine();
                    }
                    catch(Exception e)
                    {
                        System.out.println("Fail to write it back");
                    }
                }
            }

            if(ct.equalsIgnoreCase("y"))
            {
        		System.out.println("Requesting a new Token from GroupServer to Connect the FileServer...");
                FCToken = groupClient.getToken_connectToFileServer(username, new ArrayList<String>(token.getGroups()), fsPubKey);
                if(FCToken != null)
                {
                    System.out.print("Authenticating FileServer...");
            		if(!fileClient.authenticate(FCToken, pubKey, privKey, fsPubKey)) {
            			System.out.println("Authentication Failed!");
            		} else {
            			System.out.println("Successfully Authenticated!");
                        fs_authentication = true;
            		}
                }
                else
                {
                    System.out.println("Fail to get an valid token to communicate with the file server");
                    if(fileClient.isConnected())
                        fileClient.disconnect();
                }
            }
            else
            {
                System.out.println("Connection between the file server and client is closing. You can choose to connect another file server later.");
                if(fileClient.isConnected())
                    fileClient.disconnect();
            }
        }
        System.out.println("Returning to main menu...");
    }
    
    public static void delFile() {
        System.out.print("You have chosen to delete a file. Press 1 to continue. Press another number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(!fileClient.isConnected()) {
            System.out.println("You must be connected to a fileserver to use this function");
        }
        else if(choice == 1)
        {
            boolean success = false;
            do {
                System.out.print("Please enter the path of the file you want to delete: ");
                String path = input.nextLine();
                success = fileClient.delete(path, FCToken);
                if(success) {
                    System.out.printf("Successfully deleted %s\n", path);
                } else {
                    System.out.print("Delete unsuccessful, try again? (y/n): ");
                    if(input.nextLine().equals("n")) {
                        break;
                    }
                }
            } while(!success);
        }
        System.out.println("Returning to main menu...");
    }
    
    public static void downloadFile() {
        System.out.print("You've chosen to download a file. Press 1 to continue, or another number to return to the menu. ");
        choice = input.nextInt();
        input.nextLine();
        if(!fileClient.isConnected()) {
            System.out.println("You must be connected to a fileserver to use this function");
        }
        else if(choice == 1)
        {
            boolean success = false;
            do {
                System.out.print("Please enter source file path: ");
                String src = input.nextLine();
                System.out.print("Please enter your destination file path: ");
                String dest = input.nextLine();
                boolean proceed = true;
                if(EDToken == null)
                {
                    EDToken = groupClient.getToken_fileOperation(username, new ArrayList<String>(token.getGroups()));
                    if(EDToken == null)
                    {
                        proceed = false;
                        System.out.println("Sorry, you can't download file because you can't have the proper token.");
                    }
                }
                else
                {
                    if(verfify_timeOut())
                    {
                        //if time out, request a new token
                        EDToken = groupClient.getToken_fileOperation(username, new ArrayList<String>(token.getGroups()));
                        if(EDToken == null)
                        {
                            proceed = false;
                             System.out.println("Sorry, you can't download file because you can't have the proper token.");
                        }
                    }
                }
                if(proceed)
                {
                    
                    boolean stayinGroups = groupsCheck();
                    if(stayinGroups)
                    {
                        String grp = selectGroup();
                        if(!grp.equals(""))
                        {
                            success = fileClient.download(src, dest, grp, FCToken, EDToken.getKeys());
                            if(success) {
                                System.out.println("Download successful!");
                            } else {
                                System.out.print("Download unsuccessful, try again? (y/n): ");
                                if(input.nextLine().equals("n")) {
                                    break;
                                }
                            }
                        }
                    }
                }
            } while(!success);
        }
        System.out.println("Returning to main menu...");
    }
    
    public static void uploadFile() {
        System.out.print("You've chosen to upload a file. Press 1 to continue, or another number to return to the menu. ");
        choice = input.nextInt();
        input.nextLine();
        if(!fileClient.isConnected()) {
            System.out.println("You must be connected to a fileserver to use this function");
        }
        else if(choice == 1)
        {
            boolean success = false;
            do {
                System.out.print("Please enter source file path: ");
                String src = input.nextLine();
                System.out.print("Please enter your destination file path: ");
                String dest = input.nextLine();    
				//System.out.println("Please enter the group you would like to upload to: ");
                boolean stayinGroups = groupsCheck();
                if(stayinGroups)
                {
                    String grp = selectGroup();
                    boolean proceed = true;
                    if(!grp.equals(""))
                    {
        				
                        //request token from the group server - we always want the newest key list
                        ArrayList<String> working_group = new ArrayList<String>();
                        working_group.add(grp);
                        EDToken = groupClient.getToken_fileOperation(username, working_group);

                        if(EDToken == null || verfify_timeOut())
                        {
                               //because the fresh token can never be time out
                                proceed = false;
                                System.out.println("Sorry. You have no rights to upload file");
                        }
                        if(proceed)
                        {
                            success = fileClient.upload(src, dest, grp, FCToken, EDToken.getKeys());
                            if(success) {
                                System.out.println("Upload successful!");
                            }else {
                                System.out.print("Upload unsuccessful, try again? (y/n): ");
                                if(input.nextLine().equals("n")) {
                                    break;
                                }
                            }
                        }
                    }
                }
                else
                {
                    break;
                }
            } while(!success);
        }
        System.out.println("Returning to main menu...");
    }
    
    public static void listFiles() {
        System.out.print("You have chosen to list files. Press 1 to continue. Press another number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(!fileClient.isConnected()) {
            System.out.println("You must be connected to a fileserver to list files");
        }
        if(choice == 1)
        {
            ArrayList<String> allFiles = (ArrayList<String>)fileClient.listFiles(FCToken);
            if(allFiles == null || allFiles.isEmpty()) {
                System.out.println("Sorry, You did not have any file now\n");
				
			} else {
				for(String file : allFiles) {
					System.out.println(file);
				}
			}
        }
        System.out.println("Returning to main menu...");
    }
    
    public static void printGroups()
    {
        ArrayList<String> groups = new ArrayList<String>(token.getGroups());
        if(groups != null && groups.size() != 0)
        {
            System.out.println("Here are your groups");
            int i = 0;
            for(; i < groups.size(); i++)
            {
                System.out.println(""+ (i+1) + ". " + groups.get(i));
            }
        }
        else
        {
            System.out.println("Sorry. You don't belong to any group yet. Try to be in group first!");
        }
    }
    
    public static void printGroups(UserToken workingtoken)
    {
        if(workingtoken == null) {
			System.out.println("Invalid token");
			return;
		}
		ArrayList<String> groups = new ArrayList<String>(workingtoken.getGroups());
        if(groups != null && groups.size() != 0)
        {
            System.out.println("Here are your groups");
            int i = 0;
            for(; i < groups.size(); i++)
            {
                System.out.println(""+ (i+1) + ". " + groups.get(i));
            }
        } else {
            System.out.println("Sorry. You don't belong to any group yet. Try to be in group first!");
        }
    }
    
    public static void end()
    {
        System.out.print("You have chosen to disconnect. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
            groupClient.disconnect();
            if(fileClient.isConnected()) fileClient.disconnect();
            System.out.println("You have disconnected from the system successfully! Exiting the application!");
            input.close();
            System.exit(0);
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void checkIdentity()
    {
        //token = groupClient.getToken(username);
        if(token == null)
        {
            System.out.println("Sorry, you have been deleted from the system by Administrator. You are forced to exit");
            groupClient.disconnect();
            if(fileClient.isConnected()) fileClient.disconnect();
            input.close();
            System.exit(0);
        }
    }
    
    public static void changeGroups()
    {
		masterToken = groupClient.getToken(username);
        printGroups(masterToken);
		if(masterToken == null) {
            System.out.println("Sorry, you can't change your working groups because your master token is not valid");
			return;
		}
        if(masterToken.getGroups().size() > 0)
        {
            System.out.println("Please enter the numbers of your desired groups, separated by spaces. \nWhen you are finished, type 'done' and press enter.");
            ArrayList<String> groups = new ArrayList<String>();
            while(input.hasNextInt()) {
                choice = input.nextInt();
				//input.nextLine();
                if(choice > 0 && choice <= token.getGroups().size() + 1) {
                    groups.add(masterToken.getGroups().get(choice - 1));
                }
            }
			while(input.hasNext("\n")) { input.next(); }
			input.nextLine();
			System.out.println("Here are the group's you've selected:");

			for(String group : groups) {
				System.out.println(group);
			}

			System.out.print("Is this correct?(y/n): ");
			if(input.nextLine().charAt(0) != ('y')) {
				System.out.println("Returning to main menu...");
				return;
			}
			token = groupClient.getToken(username, groups);
			System.out.println("successfully updated token!");
        }
        else
        {
            System.out.println("Sorry, you can't change your working groups because you are not in any group yet");
        }
    }

    public static boolean groupsCheck()
    {
        if(token == null) {
            System.out.println("Invalid token");
            return false;
        }
        ArrayList<String> groups = new ArrayList<String>(token.getGroups());
        if(groups != null && groups.size() != 0)
        {
            System.out.println("Here are your groups");
            int i = 0;
            for(; i < groups.size(); i++)
            {
                System.out.println(""+ (i+1) + ". " + groups.get(i));
            }
        } 
        else 
        {
            System.out.println("Sorry. You don't belong to any group yet. Try to be in group first!");
            return false;
        }
        System.out.print("Does this list include the group you want to work on? (y/n): ");
        if((input.nextLine()).charAt(0) == 'y')
            return true;
        return false;
    }

    public static String selectGroup()
    {
        String group_to_be_returned = "";
        char response;
        do
        {
			if(token.getGroups().size() == 0) {
				System.out.println("You don't belong to any groups yet.");
				group_to_be_returned = "";
                break;
			}
            else 
            {
                printGroups(token);
                System.out.print("Please enter the group name you would like to operate on: ");
                String groupName = input.nextLine();
                if(token.getGroups().contains(groupName))
                {
				    group_to_be_returned = groupName;
                    break;
                }
			}
            System.out.println("Sorry, your entered name is not valid, please try again. If you would like to choose a group not in the list, you need to change your working groups");
			System.out.print("Would you like to try again? (y/n): ");
            response = input.nextLine().charAt(0);
        } while(response == 'y');
		
        return group_to_be_returned;
	}

    public static boolean verfify_timeOut()
    {
        if((new Date()).getTime() - EDToken.getCreatedTime() < 600000)
        {
            return false;
        }
        return true;
    }

	public static void approveRequests() {
        System.out.print("You've chosen to see all the pending requests. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
    		if (token != null) 
            {
    			Hashtable<String, PublicKey> reqs = (Hashtable<String, PublicKey>)groupClient.lUserRequests(token);
                if(reqs != null && reqs.size() != 0)
                {
                    System.out.println("Here are the user requests waiting to be approved");
                    //iterate all the user name and print out 
                    int i = 1;
                    Set<String> keys = reqs.keySet();
                    for(String key: keys)
                    {
                        System.out.println(i + ". "+key);
                    }
                    String choice = "";
                    System.out.print("Does this list contains any user you want to create? y/n ");
                    choice = input.nextLine();
                    if(choice.equalsIgnoreCase("y"))
                    {
                        choice = "";   
                        do
                        {
                            System.out.print("Please enter the user name to indicate which user you would like to approve: ");
                            choice = input.nextLine();
                        }
                        while(!reqs.containsKey(choice));
                        if(groupClient.createUser(choice, token, reqs.get(choice)))
                            System.out.println("Congratulations! You have created user " + choice + " successfully!");
                        else
                            System.out.println("Sorry. You fail to create this user. Please try other options.");
                    }
                }
                else
                {
                    System.out.println("There is no pending request.");
                }
    		} 
            else 
            {
    			System.out.println("Invalid token.");
    		}
        }
        System.out.println("Returning to main menu...");
	}

	public static boolean requestNewUser() throws Exception{
		String uname = null;
		PublicKey pubkey = null;

		System.out.print("Please enter your desired username: ");
		username = input.nextLine();

		//read the key pair file to see whether the user exists already.
		ObjectInputStream userPubKeysStream = new ObjectInputStream(new FileInputStream("UserPublicKeys.bin"));
		Hashtable<String, PublicKey> user_publicKeys = (Hashtable<String, PublicKey>)userPubKeysStream.readObject();
		userPubKeysStream.close();

		boolean existed = false;
		//if not, create a new key pair and add it into the file
		if(user_publicKeys == null || !user_publicKeys.containsKey(username))
        {
			System.out.print("Please create a password for your account: ");
			String user_password = input.nextLine();

			//generate a key pair for the first user, store the user and public key in one file, and store the user and the encrypted private key in another file
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
			kpg.initialize(3072, new SecureRandom());
			KeyPair kp = kpg.genKeyPair();
			pubKey = kp.getPublic();
			privKey = kp.getPrivate();
			user_publicKeys.put(username, pubKey);
                
			//write the updated table back to the file 
			ObjectOutputStream uPubKOutStream = new ObjectOutputStream(new FileOutputStream("UserPublicKeys.bin"));
			uPubKOutStream.writeObject(user_publicKeys);
			uPubKOutStream.close();
                
			//hash the user's password and make it to be the secret key to encrypt the private keys 
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update(user_password.getBytes());
			byte[] hashedPassword = messageDigest.digest();
                
			//Actually encrypt the user's private key 
			Cipher ucipher = Cipher.getInstance(AES_Method, "BC");
			//create a shared key with the user's hashed password 
			SecretKey generated_skey = new SecretKeySpec(hashedPassword, "AES");

			//generate a 16-bit salt
			SecureRandom random = new SecureRandom();
			byte[] user_salt = new byte[16];
			random.nextBytes(user_salt);

			IvParameterSpec user_ivSpec = new IvParameterSpec(user_salt);

			ucipher.init(Cipher.ENCRYPT_MODE, generated_skey, user_ivSpec);
                
			byte[] key_data = (privKey).getEncoded();
			byte[] encrypted_data = ucipher.doFinal(key_data);
                
			FileInputStream uPrivis = new FileInputStream("UserPrivateKeys.bin");
			ObjectInputStream userPrivKeysStream = new ObjectInputStream(uPrivis);
			Hashtable<String, ArrayList<byte[]>> user_privKeys = (Hashtable<String, ArrayList<byte[]>>)userPrivKeysStream.readObject();
			uPrivis.close();
			userPrivKeysStream.close();

			ArrayList<byte[]> salt_priv = new ArrayList<byte[]>();
			salt_priv.add(encrypted_data);
			salt_priv.add(user_salt);
			user_privKeys.put(username, salt_priv);

			//write the updated table back to the file 
			FileOutputStream uPrivos = new FileOutputStream("UserPrivateKeys.bin");
			ObjectOutputStream uPrivKOutStream = new ObjectOutputStream(uPrivos);
			uPrivKOutStream.writeObject(user_privKeys);
			uPrivos.close();
			uPrivKOutStream.close();
		} 
        else 
        {
			System.out.println("Sorry, you're not allowed to create your user account because this username is used. Please try another one later.");
            System.out.println("Exiting the application-----------------------------------------------------");
            groupClient.disconnect();
            System.exit(-1);
		}		

		//request the public key from group server because it is the first time to connect. 
		PublicKey gsPubKey = groupClient.getGSkey();
        System.out.println("Getting key from group server");
        String ct = "";      
        if(gsPubKey == null)
        {
                System.out.println("Fail to get Group Server's publc key.");
                System.out.println("Exiting the application-----------------------------------------------------");
                groupClient.disconnect();
                System.exit(-1);
        }
        else
        {
                ArrayList<PublicKey> gs_pubKeys = new ArrayList<PublicKey>();

                gs_pubKeys.add(gsPubKey);
                //write server's public key to a file 
                try
                {
                    ObjectOutputStream sPubKOutStream = new ObjectOutputStream(new FileOutputStream("GSPublicKey_client.bin"));
                    sPubKOutStream.writeObject(gs_pubKeys);
                    sPubKOutStream.close();
                    //print public key out for user to verify 
                    System.out.println("RSA Key is: " + DatatypeConverter.printBase64Binary(gsPubKey.getEncoded()));
                    System.out.print("Do you want to continue? y/n: ");
                    ct = input.nextLine();
                }
                catch(Exception e)
                {
                    System.out.println("Fail to write it back");
                    System.out.println("Exiting the application-----------------------------------------------------");
                    groupClient.disconnect();
                    System.exit(-1);
                }
        }
        if(ct.equalsIgnoreCase("y"))
        {
    		//pack username and public key
    		ArrayList<byte[]> request = new ArrayList<byte[]>();
    		request.add(username.getBytes());
    		request.add(gsPubKey.getEncoded());
    		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    		ObjectOutputStream objOut = new ObjectOutputStream(bOut);
    		objOut.writeObject(request);
    		byte[] reqBytes = bOut.toByteArray();
    		byte[] encReqBytes = new byte[(3072/8) * 2]; //enough space for two items encrpyted with the 3072 bit server public key

    		//encrypt packed bytes with group server's public key
    		try 
            {
    			Cipher cipher = Cipher.getInstance("RSA", "BC");
    			cipher.init(Cipher.ENCRYPT_MODE, gsPubKey);
    			byte[] enc1 = cipher.doFinal(Arrays.copyOfRange(reqBytes, 0, reqBytes.length/2));
    			byte[] enc2 = cipher.doFinal(Arrays.copyOfRange(reqBytes, reqBytes.length/2, reqBytes.length));
    			System.arraycopy(enc1, 0, encReqBytes, 0, enc1.length);
    			System.arraycopy(enc2, 0, encReqBytes, enc1.length, enc2.length);
    		} 
            catch(Exception e)
            {
    			System.err.println("Error encrypting user creation request (RSA): ");
    			e.printStackTrace();
    			System.out.println("Exiting the application-----------------------------------------------------");
                groupClient.disconnect();
                System.exit(-1);
    		}
    		
    		//let groupClient handle communication with server
    	    if(groupClient.requestUser(encReqBytes))
            {
    			System.out.print("Request successfully submitted! You have to log in again.");
    			System.out.println("Exiting the application-----------------------------------------------------");
                groupClient.disconnect();
                System.exit(-1);
    		} 
            else 
            {
    			return false;
    		}	
        }
        else
        {
             System.out.println("Fail to verify Group Server's publc key.");
             System.out.println("Exiting the application-----------------------------------------------------");
             groupClient.disconnect();
             System.exit(-1);
        }
        return false;
	}
}
