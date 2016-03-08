import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;

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
    private static final int GS_PORT = 8765;
    private static final int FS_PORT = 4321;
    
    public static void main(String[] args)
    {
        //create a new group client and file client
        groupClient = new GroupClient();
        fileClient = new FileClient();
        input = new Scanner(System.in);
        
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
        
        do {
            System.out.print("Please enter your username to log in: ");
            username = input.nextLine();
            masterToken = groupClient.getToken(username); //get a token for this user
            token = masterToken;
            if(masterToken == null)
            {
                System.out.print("Sorry, you do not belong to this group server. Try again? (y/n): ");
                String response = input.nextLine();
                if(!response.equals("y")) {
                    groupClient.disconnect();
                    input.close();
                    System.exit(0);
                }
            }
        } while(masterToken == null);
        
        System.out.printf("Welcome %s!\n", username);
		input.nextLine();
		input.nextLine();
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
            default:
                end();
                break;
        }
    }
    
    public  static void cuser()
    {
        System.out.print("You have chose to create user. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
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
                System.out.println("Congratulations! You have deleted user " + deletedUserName + " successfully!");
            else
                System.out.println("Sorry. You fail to delete this user. Please try other options.");
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void cgroup()
    {
        System.out.print("You have chose to create a new group. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
            System.out.print("Please Enter the group name you would like to create: ");
            String groupName = input.nextLine();
            if(groupClient.createGroup(groupName, token))
                System.out.println("Congratulations! You have created the new group " + groupName + " successfully!");
            else
                System.out.println("Sorry. You fail to create this group. Please try other options.");
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void dgroup()
    {
        System.out.print("You have chose to delete a new group. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
            System.out.print("Please Enter the group name you would like to delete: ");
            String groupName = input.nextLine();
            if(groupClient.deleteGroup(groupName, token))
                System.out.println("Congratulations! You have deleted the new group " + groupName + " successfully!");
            else
                System.out.println("Sorry. You fail to delete this group. Please try other options.");
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
            System.out.print("Please Enter the group name you would like to add: ");
            String groupName = input.nextLine();
            if(groupClient.addUserToGroup(userName, groupName, token))
                System.out.println("Congratulations! You have added the user " + userName +" to the group " + groupName + " successfully!");
            else
                System.out.println("Sorry. You fail to add this user to the group. Please try other options.");
            
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void removeUser()
    {
        System.out.print("You have chose to delete a user from a group. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
            System.out.println();
            System.out.print("Please Enter the Username to be deleted: ");
            String userName = input.nextLine();
            System.out.print("Please Enter the group name which the user belongs to: ");
            String groupName = input.nextLine();
            if(groupClient.deleteUserFromGroup(userName, groupName, token))
                System.out.println("\nCongratulations! You have deleted the user " + userName +" from the group " + groupName + " successfully!");
            else
                System.out.println("\nSorry. You fail to delete this user from the group. Please try other options.");
            
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
            token = groupClient.getToken(username);
            System.out.print("Please Enter the group name which you would like to see all the members: ");
            String groupName = input.nextLine();
            List<String> members = groupClient.listMembers(groupName, token);
            if(members != null && !members.isEmpty())
            {
                System.out.println("\nCongratulations! You have fetched all the memers from the group " + groupName + " successfully!");
                System.out.println("Start to list");
                for(int i = 0; i < members.size(); i++)
                {
                    System.out.println(""+ (i+1) + ". " + members.get(i));
                }
            }
            else
                System.out.println("Sorry. You fail to list members of this group. Please try other options.");
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
                System.out.print("Please enter the group you would like to upload to: ");
                String grp = input.nextLine();
                success = fileClient.upload(src, dest, grp, token);
                if(success) {
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
            fileClient.disconnect();
            System.out.println("You have disconnected from the server successfully! Exiting the application!");
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
            System.out.println("Please enter the numbers of your desired groups, separated by spaces. \nWhen you are finished, type a 'done' and press enter.");
            ArrayList<String> groups = new ArrayList<String>();
            while(input.hasNextInt()) {
                choice = input.nextInt();
				//input.nextLine();
                if(choice > 0 || choice < (token.getGroups().size())) {
                    groups.add(masterToken.getGroups().get(choice - 1));
                }
            }
			while(input.hasNext("\n")) { input.next(); }
			input.nextLine();
			System.out.println("Here are the group's you've selected:");

			for(String group : groups) {
				System.out.println(group);
			}

			System.out.println("Is this correct?");
			if(input.nextLine().charAt(0) != ('y')) {
				System.out.println("Returning to main menu...");
				return;
			}
			token = groupClient.getToken(username, groups);
			System.out.println("successfully updated token!");
        }
    }
}
