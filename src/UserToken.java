
import java.util.*;
import java.security.*;
import javax.crypto.*;

/**
 * A simple interface to the token data structure that will be
 * returned by a group server.  
 *
 * You will need to develop a class that implements this interface so
 * that your code can interface with the tokens created by your group
 * server.
 *
 */
public interface UserToken
{
    /**
     * This method should return a string describing the issuer of
     * this token.  This string identifies the group server that
     * created this token.  For instance, if "Alice" requests a token
     * from the group server "Server1", this method will return the
     * string "Server1".
     *
     * @return The issuer of this token
     *
     */
    public String getIssuer();


    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public String getSubject();


    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public List<String> getGroups();

    /* This method returns the time when the token is created
       This method will be used when the user needs to upload/download file
    */
    public long getCreatedTime();

    /* This method returns the key List embedded in the token 
       This method will be used when the user needs to upload/download file
    */
    public ArrayList<SecretKey> getKeys();

    /* This method returns the encrypted time when the token is created
       This method will be used when the user needs to communicate with the file server
    */
    public byte[] getEncryptedTime();

	/** This method initializes the signature on a token.
	 *
	 *@params The signing private key
	 */
	public void tokSign(PrivateKey privateKey) throws InvalidKeyException, SignatureException;

	/**
	 *This method will verify the signature attached to this token.
	 *Returns true if the authenticity can be verified, false otherwise.
	 *
	 *@params The public key to verify against
	 *@return true if verification success, false otherwise
	 */
	public boolean tokVerify(PublicKey publicKey) throws InvalidKeyException, SignatureException;

}   //-- end interface UserToken
