import java.io.*;
import java.util.*;
import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class ClientApp
{
    private static GroupClient groupClient;
    private static FileClient fileClient;
    private static Scanner input;
    private static UserToken masterToken;
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
       

        //genereate a 256-bit AES key for securely transmission
        KeyGenerator key = KeyGenerator.getInstance("AES/CBC/PKCS5Padding", "BC");
        key.init(256, new SecureRandom());
        AES_key = key.generateKey();
      
        PublicKey pubKey = null;
        PrivateKey privKey = null;

        do {
            System.out.print("Please enter your username to log in: ");
            username = input.nextLine();
            
            //read the key pair file to see whether the user exists already.
            ObjectInputStream userPubKeysStream = new ObjectInputStream( new FileInputStream("UserPublicKeys.bin"));
            Hashtable<String, PublicKey> user_publicKeys = (Hashtable<String, PublicKey>)userPubKeysStream.readObject();
            
            //if not, create a new key pair and add it into the file
            if(!user_publicKeys.contains(username))
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
                SecretKey generated_skey = new SecretKeySpec(hashedPassword, 0, hashedPassword.length, "AES");
                ucipher.init(Cipher.ENCRYPT_MODE, generated_skey);
                
                byte[] key_data = (privKey).getEncoded();
                byte[] encrypted_data = ucipher.doFinal(key_data);
                
                 //read the key pair file to see whether the user exists already.
                ObjectInputStream userPrivKeysStream = new ObjectInputStream(new FileInputStream("UserPrivateKeys.bin"));
                Hashtable<String, byte[]> user_privKeys = (Hashtable<String, byte[]>)userPrivKeysStream.readObject();
                user_privKeys.put(username, encrypted_data);

                //write the updated table back to the file 
                ObjectOutputStream uPrivKOutStream = new ObjectOutputStream(new FileOutputStream("UserPrivateKeys.bin"));
                uPrivKOutStream.writeObject(user_privKeys);
                uPrivKOutStream.close();
            }
            else
            {
                pubKey = user_publicKeys.get(username);
                System.out.print("Please enter your password: ");
                String user_password = input.nextLine();

                //hash the user's password and make it to be the secret key to encrypt the private keys 
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                messageDigest.update(user_password.getBytes());
                byte[] hashedPassword = messageDigest.digest();

                ObjectInputStream userPrivKeysStream = new ObjectInputStream(new FileInputStream("UserPrivateKeys.bin"));
                Hashtable<String, byte[]> user_privKeys = (Hashtable<String, byte[]>)userPrivKeysStream.readObject();
                byte[] key_data = user_privKeys.get(username);
                //decrypt the one read from the file to get the server's private key 
                Cipher cipher_privKey = Cipher.getInstance(AES_Method, "BC");
                //create a shared key with the user's hashed password 
                SecretKey skey = new SecretKeySpec(hashedPassword, 0, hashedPassword.length, "AES");
                cipher_privKey.init(Cipher.DECRYPT_MODE, skey);
                byte[] decrypted_data = cipher_privKey.doFinal(key_data);
                
                KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
                privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decrypted_data));
            }

            //read in server's public key from the file storing server's public key 
            FileInputStream kfis = new FileInputStream("ServerPublic.bin");
            ObjectInputStream serverKeysStream = new ObjectInputStream(kfis);
            PublicKey sevPubKey = (PublicKey)serverKeysStream.readObject();

            //authenticate process to check whether the authentication succeeds. 
            boolean verified = groupClient.authenticate(username, privKey, sevPubKey, AES_key);
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
                System.out.print("Sorry, the authentication fails. Try again? (y/n): ");
                String response = input.nextLine();
                if(!response.equalsIgnoreCase("y")) {
                    groupClient.disconnect();
                    input.close();
                    System.exit(0);
                }
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
            if(fileClient.isConnected()) {
                System.out.println("11. Delete file");
                System.out.println("12. Download file");
                System.out.println("13. Upload file");
                System.out.println("14. List all accessible files");
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
            if(choice < 0 || choice > 14)
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
                    try
                    {
                        cuser();
                    }
                    catch (Exception e)
                    {
                        System.err.println("Error: " + e.getMessage());
                        e.printStackTrace(System.err);
                    }
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
                default:
                    end();
                    break;
			}
		} else {
                System.out.println("Sorry, you're deleted by ADMIN. Forced to log out");
                end();
		}
	}
        
    public static void cuser() throws Exception
    {
        System.out.print("You have chose to create user. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
			System.out.println("Disallowed characters: '&' and  ','");
            System.out.print("Please Enter the Username you would like to create: ");
            String createdUserName = input.nextLine();

            //the ADMIN needs to know the public key of the user
            ObjectInputStream userKeysStream = new ObjectInputStream(new FileInputStream("UserPublicKeys.bin"));
            Hashtable<String, PublicKey> user_publicKeys = (Hashtable<String, PublicKey>)userKeysStream.readObject();
            //if the public key already exists, can start to create  that user 
            if(user_publicKeys.contains(createdUserName))
            {
                if(groupClient.createUser(createdUserName, token, (user_publicKeys.get(createdUserName))))
                    System.out.println("Congratulations! You have created user " + createdUserName + " successfully!");
                else
                    System.out.println("Sorry. You fail to create this user. Please try other options.");
            }
            else
            {
                //if the key pair is not stored yet, the ADMIN can't create that user 
                System.out.println("Sorry, this user does not have key pairs on file. Please check back later.");
            }
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
                System.out.println("Congratulations! You have deleted user " + deletedUserName + " successfully!");
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
            printGroups(token);
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
                    List<String> members = groupClient.listMembers(groupName, token);
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
            if(fs_port == 0)
            {
                fs_port = FS_PORT;
            }
            if(!fileClient.connect(fs_name, fs_port)) {
                fs_name = null;
                fs_port = 0;
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
                success = fileClient.delete(path, token);
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
                success = fileClient.download(src, dest, token);
                if(success) {
                    System.out.println("Download successful!");
                } else {
                    System.out.print("Download unsuccessful, try again? (y/n): ");
                    if(input.nextLine().equals("n")) {
                        break;
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
				System.out.println("Please enter the group you would like to upload to: ");
				String grp = input.nextLine();

                if(fileClient.upload(src, dest, grp, token)) {
					System.out.println("Upload successful!");
                } else {
					System.out.print("Upload unsuccessful, try again? (y/n): ");
					if(input.nextLine().equals("n")) {
						break;
                    }
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
            ArrayList<String> allFiles = (ArrayList<String>)fileClient.listFiles(token);
            if(allFiles.isEmpty())
                System.out.println("Sorry, You did not have any file now\n");

            for(String file : allFiles) {
                System.out.println(file);
            }
        }
        System.out.println("Returning to main menu...");
    }
    
    public static void printGroups()
    {
        ArrayList<String> groups = new ArrayList<>(token.getGroups());
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
		ArrayList<String> groups = new ArrayList<>(workingtoken.getGroups());
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
    }

    public static boolean groupsCheck()
    {
        printGroups(token);
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
            printGroups(token);
            System.out.print("Please enter the group name you would like to operate on: ");
            String groupName = input.nextLine();
			if(token.getGroups().size() == 0) {
				System.out.println("You don't belong to any groups yet.");
				group_to_be_returned = "";
                break;
			}
            else if(token.getGroups().contains(groupName)) {
				group_to_be_returned = groupName;
                break;
			}
            System.out.println("Sorry, your entered name is not valid, please try again. If you would like to choose a group not in the list, you need to change your working groups");
			System.out.print("Would you like to try again? (y/n): ");
            response = input.nextLine().charAt(0);
        } while(response == 'y');
		
        return group_to_be_returned;
	}
}
