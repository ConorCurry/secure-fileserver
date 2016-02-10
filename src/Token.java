import java.util.List;
import java.util.ArrayList;

public class Token implements UserToken {

    private String gsName;
    private String username;
    private ArrayList<String> accessibleGroups;

    public Token(String gsName, String username, ArrayList<String> accessibleGroups) {
        this.gsName = gsName;
        this.username = username;
        this.accessibleGroups = new ArrayList<String>(accessibleGroups);
    }

    public String getIssuer() {
        return gsName;        
    }
    public String getSubject() {
        return username;
    }
    public List<String> getGroups() {
        return accessibleGroups;
    }
}
