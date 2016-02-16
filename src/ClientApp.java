import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;

public class ClientApp
{
    private static GroupClient groupClient;
    private static FileClient fileClient;
    private static Scanner input;
    private static UserToken token;
    private static int choice;
    private static String username;
    private static String gs_name, fs_name;
    private static int fs_port, gs_port;
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
            token = groupClient.getToken(username); //get a token for this user
            if(token == null)
            {
                System.out.print("Sorry, you do not belong to this group server. Try again? (y/n): ");
                String response = input.nextLine();
                if(!response.equals("y")) {
                    groupClient.disconnect();
                    input.close();
                    System.exit(0);
                }
            }
        } while(token == null);
        
        System.out.printf("Welcome %s!\n", username);
        while(true) {
            printGroupMenu();
        }
    }
    //public 
    
    public static void printGroupMenu()
    {
        
        System.out.println("\nMain Menu: ");
        System.out.println("------------Please choose the number of what you want to do from the following options-------\n");
        System.out.println("1. Create User");
        System.out.println("2. Delete User");
        System.out.println("3. Create Group");
        System.out.println("4. Delete Group");
        System.out.println("5. Add User To Group");
        System.out.println("6. Delete User From Group");
        System.out.println("7. List members of a group");
        System.out.println("8. Modify fileserver connection");
        System.out.println("9. Download file");
        System.out.println("10. Upload file");
        System.out.println("11. List all accessible files");
        System.out.println("12. Disconnect from the server and exit the application");
        System.out.print("\nPlease enter your choice: ");
        
        //check whether the choice is valid
        while(true){
            try
            {
                choice = input.nextInt();
            }
            catch(Exception e)
            {
                System.out.println("Sorry, Your choice is not valid, please enter a valid number.");
                continue;
            }
            if(choice < 1 || choice > 12)
            {
                System.out.println("Sorry, Your choice is not valid, please enter a valid number.");
            }
            else break;
        }
        input.nextLine();
        
        //TODO: maybe break up into some submenus?
        switch(choice){
            case 1:
                cuser();
                break;
                
            case 2:
                duser();
                break;
                
            case 3:
                cgroup();
                break;
                
            case 4:
                dgroup();
                break;
                
            case 5:
                addUser();
                break;
                
            case 6:
                removeUser();
                break;
                
            case 7:
                listAll();
                break;
                
            case 8:
                connectFileserver();
                break;
                
            case 9:
                delFile();
                break;
            
            case 10:
                downloadFile();
                break;
                
            case 11:
                uploadFile();
                break;
                
            case 12:
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
                System.out.println("Sorry. You fail to delete this user from the group. Please try other options.");
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
            fileClient.connect(fs_name, fs_port);
        }
        System.out.println("Returning to main menu...");
        
    }
    
    public static void delFile() {
        System.out.print("You have chosen to delete a file. Press 1 to continue. Press another number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
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
    
    }
    
    public static void uploadFile() {
    
    }
    
    public static void listFiles() {
    
    }
    
    public static void end()
    {
        System.out.print("You have chosen to disconnect. Press 1 to continue. Press other number to go back to main menu: ");
        choice = input.nextInt();
        input.nextLine();
        if(choice == 1)
        {
            groupClient.disconnect();
            System.out.println("You have disconnected from the server successfully! Exiting the application!");
            input.close();
            System.exit(0);
        }
        System.out.println("Going back to main menu............................................\n");
    }
}
