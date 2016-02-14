import java.util.Scanner;

public class GroupClientApp
{
	private GroupClient groupClient;
	private Scanner input;
	private int times = 1;
	private UserToken token;

	public static void main(String[] args)
	{
	    //create a new group client 
	    groupClient = new GroupClient();
	    input = new Scanner(System.in);
		
	    //connect to the group server 
		String server;
		int port;
		if(args.length == 0
		{
			server = 
			port = GroupSever.SERVER_PORT;	
		}
		else
		{
			server = args[0];
			port = Integer.ParseInt(args[1]);
		}
		groupClient.connect(server, port);
		while(true)
		{
			printMainMenu();
			times++;
		}
	}

	public void printMainMenu()
	{
		System.out.println("------------Welcome to CS1653 Group-Based File Sharing application------------\n");
		
		//if the user just open the application. 
		if(times == 1)
		{
			System.out.println("Please enter your username:")
			String username = input.nextLine();

		}
		else
		{	
			System.out.println("------------Please choose what you want to do from the following options-------\n");
			System.out.println("1. ")
		}

	}



}