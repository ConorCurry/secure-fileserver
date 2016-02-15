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
    private static String group_work;
    
    public static void main(String[] args)
    {
        //create a new group client and file client
        groupClient = new GroupClient();
        fileClient = new FileClient();
        input = new Scanner(System.in);
        System.out.println("------------Welcome to CS1653 Group-Based File Sharing application--------------------------------------\n");
        System.out.print("Please Enter the port number for connecting to the group server, put 0 if you want to use default value: ");
        int port_server = input.nextInt();
        System.out.print("\nPlease Enter the port number for connecting to the file server, put 0 if you want to use default value: ");
        int port_file = input.nextInt();
        if(port_server == 0) port_server = 8765;
        if(port_file == 0) port_file = 4321;

        fileClient.connect("localhost", port_server);
        groupClient.connect("localhost", port_file);

        //get token user.
        System.out.print("Please enter your username to log in:");
        String username; 
        while(true)
        {
          username = input.nextLine();
          if(checkValidString(username)) break;
        }
        token = groupClient.getToken(username); //get a token for this user
        if(token == null)
        {
            System.out.println("Sorry, you do not belong to this group server. Exiting.........................");
            groupClient.disconnect();
            fileClient.disconnect();
            input.close();
            System.exit(0);
        }
            
        System.out.printf("Welcome %s ! Now you are entering the main menu!", username);
        while(true)
        {
            printMenu();
        }
    }
    
    public static void printMenu()
    {
        
        System.out.println("\t\t\tMain Menu: ");
        System.out.println("------------Please choose the number of what you want to do from the following options-------\n");
        System.out.println("1. Create User");
        System.out.println("2. Delete User");
        System.out.println("3. Create Group");
        System.out.println("4. Delete Group");
        System.out.println("5. Add User To Group");
        System.out.println("6. Delete User From Group");
        System.out.println("7. List members of a group");
        System.out.println("8. List Files");
        System.out.println("9. Upload File");
        System.out.println("10. Download File");
        System.out.println("11. Delete File");
        System.out.println("12. Disconnect from the servers and exit the application");
        System.out.print("\nPlease enter your choice: ");
        
        //check whether the choice is valid
        while(checkValidInteger()){
            if(choice < 1 && choice > 12)
            {
                System.out.println("Sorry, Your choice is not valid, please enter a valid number.");
            }
            else break;
        }
        input.nextLine();
        
        switch(choice){
            case 1:
                optionOne();
                break;
                
            case 2:
                optionTwo();
                break;
                
            case 3:
                optionThree();
                break;
                
            case 4:
                optionFour();
                break;
                
            case 5:
                optionFive();
                break;
                
            case 6:
                optionSix();
                break;
                
            case 7:
                optionSeven();
                break;
                
            case 8:
                optionEight();
                break;

            case 9:
                optionNine();
                break;

            case 10:
                optionTen();
                break;

            case 11:
                optionEleven();
                break;

            default:
                optionTwelve();
                break;
        }
    }
    
    public  static void optionOne()
    {
        System.out.print("You have chose to create user. Press 1 to continue. Press other number to go back to main menu: ");
        while(checkValidInteger()){

        }
        input.nextLine();
        if(choice == 1)
        {
            System.out.print("Please Enter the Username you would like to create: ");
            String createdUserName;
            while(true)
            {
                createdUserName = input.nextLine();
                if(checkValidString(createdUserName)) break;
            }
            if(groupClient.createUser(createdUserName, token))
                System.out.println("Congratulations! You have created user " + createdUserName + " successfully!");
            else
                System.out.println("Sorry. You fail to create this user. Please try other options.");
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void optionTwo()
    {
        System.out.print("You have chose to delete user. Press 1 to continue. Press other number to go back to main menu: ");
        while(checkValidInteger()){

        }
        input.nextLine();
        if(choice == 1)
        {
            System.out.print("Please Enter the Username you would like to delete: ");
            String deletedUserName;
            while(true)
            {
                deletedUserName = input.nextLine();
                if(checkValidString(deletedUserName)) break;
            }
            if(groupClient.deleteUser(deletedUserName, token))
                System.out.println("Congratulations! You have deleted user " + deletedUserName + " successfully!");
            else
                System.out.println("Sorry. You fail to delete this user. Please try other options.");
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void optionThree()
    {
        System.out.print("You have chose to create a new group. Press 1 to continue. Press other number to go back to main menu: ");
        while(checkValidInteger()){

        }
        input.nextLine();
        if(choice == 1)
        {
            System.out.print("Please Enter the group name you would like to create: ");
            String groupName;
            while(true)
            {
                groupName = input.nextLine();
                if(checkValidString(groupName)) break;
            }
            if(groupClient.createGroup(groupName, token))
                System.out.println("Congratulations! You have created the new group " + groupName + " successfully!");
            else
                System.out.println("Sorry. You fail to create this group. Please try other options.");
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void optionFour()
    {
        System.out.print("You have chose to delete a new group. Press 1 to continue. Press other number to go back to main menu: ");
        while(checkValidInteger()){

        }
        input.nextLine();
        if(choice == 1)
        {
            System.out.print("Please Enter the group name you would like to delete: ");
            String groupName;
            while(true)
            {
                groupName = input.nextLine();
                if(checkValidString(groupName)) break;
            }
            if(groupClient.deleteGroup(groupName, token))
                System.out.println("Congratulations! You have deleted the new group " + groupName + " successfully!");
            else
                System.out.println("Sorry. You fail to delete this group. Please try other options.");
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void optionFive()
    {
        System.out.print("You have chose to add a user to a group. Press 1 to continue. Press other number to go back to main menu: ");
        while(checkValidInteger()){

        }
        input.nextLine();
        if(choice == 1)
        {
            System.out.print("Please Enter the Username to be added: ");
            String userName;
            while(true)
            {
                userName = input.nextLine();
                if(checkValidString(userName)) break;
            }
            System.out.print("Please Enter the group name you would like to add: ");
            String groupName;
            while(true)
            {
                groupName = input.nextLine();
                if(checkValidString(groupName)) break;
            }
            if(groupClient.addUserToGroup(userName, groupName, token))
                System.out.println("Congratulations! You have added the user " + userName +" to the group " + groupName + " successfully!");
            else
                System.out.println("Sorry. You fail to add this user to the group. Please try other options.");
            
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void optionSix()
    {
        System.out.print("You have chose to delete a user from a group. Press 1 to continue. Press other number to go back to main menu: ");
        while(checkValidInteger()){

        }
        input.nextLine();
        if(choice == 1)
        {
            System.out.println();
            System.out.print("Please Enter the Username to be deleted: ");
            String userName;
            while(true)
            {
                userName = input.nextLine();
                if(checkValidString(userName)) break;
            }
            System.out.print("Please Enter the group name you would like to be deleted from: ");
            String groupName;
            while(true)
            {
                groupName = input.nextLine();
                if(checkValidString(groupName)) break;
            }
            if(groupClient.deleteUserFromGroup(userName, groupName, token))
                System.out.println("\nCongratulations! You have deleted the user " + userName +" from the group " + groupName + " successfully!");
            else
                System.out.println("\nSorry. You fail to delete this user from the group. Please try other options.");
            
        }
        System.out.println("Going back to main menu............................................\n");
    }
    
    public static void optionSeven()
    {
        System.out.print("You have chose to list all the members of the group. Press 1 to continue. Press other number to go back to main menu: ");
        while(!checkValidInteger()){

        }
        input.nextLine();
        if(choice == 1)
        {
            System.out.println();
            System.out.print("Please Enter the group name which you would like to see all the members: ");
            String groupName;
            while(true)
            {
                groupName = input.nextLine();
                if(checkValidString(groupName)) break;
            }
            List<String> members = new ArrayList<String>(groupClient.listMembers(groupName, token));
            if(members != null)
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
    
    public static void optionEight()
    {
        
    }
    
    public static void optionNine()
    {

    }

    public static void optionTen()
    {

    }

    public static void optionEleven()
    {

    }

    public static void optionTwelve()
    {
        System.out.print("You have chose to exit the application. Press 1 to continue. Press other number to go back to main menu: ");
        while(checkValidInteger()){

        }
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

    public static boolean checkValidInteger()
    {
        try
        {
            choice = input.nextInt();
            return true;
        }
        catch(Exception e)
        {
            System.out.println("Sorry, Your choice is not valid, please enter a valid number.");
            return false;
        }
    }

    public static boolean checkValidString(String to_check)
    {
        if(!to_check.equals("")) return true;
        return false;
    }
}