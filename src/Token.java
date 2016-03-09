import java.util.List;
import java.util.ArrayList;
import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;

public class Token implements UserToken, java.io.Serializable{

    private String gsName;
    private String username;
    private ArrayList<String> accessibleGroups;
    private static final long serialVersionUID = -7726335089122193103L;
	private bytes[] signature;

    public Token(String gsName, String username, ArrayList<String> accessibleGroups) {
        this.gsName = gsName;
        this.username = username;
		this.signature = null;
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

	private String toString() {
		//CAUTION: THIS REQUIRES THAT '&' AND ',' BE BLACKLISTED FROM USERNAMES, GS NAMES, AND GROUPNAMES
		String strified = "";
		strified += this.username + "&" + this.gsName + "&";
		for(String group : this.accessibleGroups) {
			strified += group + ",";
		}		
	}

	public void sign(PrivateKey privateKey) {
		Signature sig = Signature.getInstance("SHA256withRSA", "BC");
		sig.initSign(privateKey);

		sig.update(this.toString().getBytes()); //signing automatically hashes
		this.signature = sig.sign();
	}

	public boolean verify(PublicKey publicKey) {
		Signature sig = Signature.getInstance("SHA256withRSA", "BC");
		sig.initVerify(publicKey);
		sig.update(this.toString().getBytes()); //signing automatically hashes
		if(sig.verify(signature)) {
			return true;
		} else {
			return false;
		}
	}
}
