import java.util.List;
import java.util.ArrayList;

public class Token implements UserToken, java.io.Serializable{

    private String gsName;
    private String username;
    private ArrayList<String> accessibleGroups;
    private static final long serialVersionUID = -7726335089122193103L;

    public Token(String gsName, String username, ArrayList<String> accessibleGroups) {
        this.gsName = gsName;
        this.username = username;
        if(accessibleGroups != null && !accessibleGroups.isEmpty())
            this.accessibleGroups = new ArrayList<String>(accessibleGroups); //new concatenation; 
        else
            this.accessibleGroups = new ArrayList<String>();
    }

    public String getIssuer() {
        return this.gsName;        
    }
    public String getSubject() {
        return this.username;
    }
    public List<String> getGroups() {
        return this.accessibleGroups;
    }
}
