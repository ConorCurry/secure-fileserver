<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>CS 1653 Project P5 Writeup</title>
  <style>
/* BEGIN CHANGES HERE */

/* In this section, you may add CSS styling if desired */
header {
  text-align: center;
}

/* END CHANGES HERE */
  </style>
  <body>
    <header>
      <h1>CS 1653 Project P5 Writeup</h1>
      <h2>
<!-- BEGIN CHANGES HERE -->

Yijia Cui yic66@pitt.edu, Conor Curry clc231@pitt.edu

<!-- END CHANGES HERE -->
      </h2>
    </header>
    <section id="overview">
      <h2>Overview</h2>
<!-- BEGIN CHANGES HERE -->

<p>In this phase, we introduce new threats to contrast our assumptions from previous phases. We now attempt to prevent information leaking from server's and clients' disks by encrypting files that must be stored. We also modify our authentication protocols to include a signed Diffie Hellman key exchange in pursuit of perfect forward secrecy. Finally, we address the possibility of compromised user private keys and defenses against that -- involving the process of associating multiple keys with a user account, and two methods for providing a secure privilege escalation policy in case of account compromise.</p>

<!-- END CHANGES HERE -->
    </section>
    <section id="threatmodel">
      <h2>Threat Model: Information Leakage from Disks</h2>
<!-- BEGIN CHANGES HERE -->

<h3>Description:</h3> 
<p>Even though the group server is entirely trustworthy for operations, all the information on the group server is stored as plain text files on disks, vulnerable to be leaked. Also, users and servers store their private keys locally and encrypted by a key derived from their passwords and SHA-256. Attackers are assumed to be able to obtain a copy of disk image from users’ and servers’ computers, and thus have access to files stored on the disk. That is, the attacker can obtain a backup of disks, and no virtual memory and no real-time running data are included. Attackers can view the plain text files, and all the information about the state of group server would be leaked. The adversary can also break the file “offline” once they obtain such a copy. Because of the fast speed of hardware nowadays, attackers can break SHA-256 keys brute-forcedly using dictionary and rainbow tables within a reasonable time and thus get the private key encrypted within it. In order to solve the problems addressed, a secure encryption method should be added to files stored on servers’ and users’ disks to ensure the confidentiality of those important information.</p>

<!-- END CHANGES HERE -->
    </section>
    <section id="attack">
      <h3>Attacks</h3>
<!-- BEGIN CHANGES HERE -->

<p>For Group Server:</p>
<p>Once the adversary has access to groupList and userList, the adversary can have all the states of users and groups stored on the group server. They will know the members of all groups and also can get list of files keys stored on GroupList. The information leakage about group membership will lead attackers to attack a specific person’s account to modify the group information and files shared. In addition, the leakage of file keys can lead to the unauthorized access to files that should only be accessed by members in a certain group. The adversary can read files with the stolen key lists and the secret inside the file is leaked. 
</p>

<p>For stored private keys:</p>
<p>The adversary can steal private keys encrypted with SHA-256 and stored on the disk. The adversary can break that encrypted file offline to get the private key. This threat leads to the private keys being compromised. The authentication is done by RSA key pairs. Once the private key is compromised, the exchanged shared key is revealed, and all the conversation will be presented to the adversary if the adversary records the communication between clients and servers. The adversary can even use the stolen private key to pretend them as a user/server.</p>

<!-- END CHANGES HERE -->
    </section>
    <section id="countermeasure">
      <h3>Countermeasures</h3>
<!-- BEGIN CHANGES HERE -->

<p>Instead of using keys derived from passwords with SHA-256 to encrypt private keys, the new algorithm, PBKDF2WithHmacSHA1, is used to derive keys from password. The iteration number of this algorithm makes it slow and hard to be broken by design.</p>

<p>With those keys, users and servers can store their private keys safely to reduce the possibility that private keys are compromised. Those keys can also use to encrypt important files, the GroupList and UserList, on the group server. The adversary could not access information in the encrypted files because they can't break the key dedrived by PBKDF2WithHmacSHA1, and thus, information stored in the encrypted files can't be leaked.</p>
    </section>

    <section id="threatmodel">
      <h2>Threat Model: Forward Secrecy Broken</h2>
<h3>Description:</h3> 
<p>In the previous threat model, the possibility for a private key being compromised is brought up. With a compromised private key, the adversary can record all the communication starting from the authentication process and break all the messages exchanged. The forward secrecy was broken in this case.</p>

</section>
    <section id="attack">
      <h2>Attacks</h2>
<p>The adversary compromises the private key first and records all the messages exchanged between the innocent user and server. Then the adversary will use the private key to get the key exchanged between them, and decrypt all the messages with the compromised shared key. That decryption of message not only reveals all the information about groups and files exchanged, it also reveals the list of keys being transmitted to the user if the user requests such a list from group server. Files shared in groups are encrypted with keys with in the list, and the adversary can use that list of file keys to decrypt those files stolen from file servers (they are untrusted).</p>

</section>
    <section id="countermeasure">
      <h3>Countermeasures</h3>
<p>Signed Diffie-Hellman protocol can be used through the authentication and key exchanges. Signed Diffie-Hellman protocol is secure because the two sides do not exchange the shared key directly. The client would generate prime BigIntegers p and g, and generate a public Diffie-Hellman key randomly from those numbers(equivalent to g^a mod p in theory). The client would sign the D-H public key, to show the identity, and then pass p and g, and the signed, D-H public key to the server. The server would verify the client's identity, use the same pair p and g to generate server's D-H keypairs, and derieve a AES key by agreeing on his generated D-H private key and the client's D-H public key (equivalent to (g^a mod p)^b = g^ab mod p). The server will sign his D-H public key(equivalent to g^b mod p in theory), send that to the client, and the client can verify the server's identity by signature and derive the same AES key by agreeing on the server's D-H public key (equivalent to (g^b mod p)^a = g^ab mod p). After this, the server and client have a shared secret key and can exchange the identity key for hmac and the nonce for message repaly/reordering. Through this procedure, a secret key is shared without transmitting a real key. The randomness generated by both sides, different p and g each time, and the difficulty of solving the discrete logarithm ensure the security of that shared key. The RSA keypairs are only used to verify the signature in this protocol. Even though the adversary records all the communciation and have the compromised private key, the adversary still can't break the shared secret key, and thus the perfect forward secrecy is provided.</p>

<section id="threatmodel">
  <h2>Threat Model: Compromised User Keys</h2>
  <h3>Description:</h3>
  <p>Currently, a major weakness of our system is the use of long term secrets – in the form of RSA keypairs – for authentication and user identification. Furthermore, while inadvisable, there is currently no way to prevent users from using a particular keypair for more than one application. Therefore, there is a large potential for these keys to be compromised over their lifetime. To fix these issues, we propose the addition of a key revocation system, as well as the ability for users to use multiple keypairs to identify themselves to the groupserver. The ability of a user to have multiple keypairs ensures they will still have access to their account in the event that one must be revoked or has been stolen. This threat motivates the creation of multiple privilege levels when interacting with a Group Server. This allows the user to work in two modes. One is mode that reflects our current implementation, where the user can request file server tokens and perform actions that may arise during normal use of the system. However, they should also be given a method for performing a privilege escalation, in order to perform administrative actions on their account. These actions include adding new authorized keys as well as revoking keys. </p>

  <h3>Attacks:</h3>
  <p>A determined attacker may find several ways to compromise keys, and most of these cannot be prevented from the perspective of the servers or client application. Without out-of-band organizational policy, there is no way that our application can enforce users using key exclusive to our application. This means that there are nearly unlimited ways that an attacker could steal a user's keys, perhaps with another application that had a compromised authentication method. Key compromise could be as simple as stealing the user's storage device – or their whole laptop. While we attempt to mitigate this threat by password protecting keys on disk, it would be detrimental to assume that no user's key could ever be stolen. It is not a “what-if” as much as a “when” in a system of any appreciable size.</p>
  <p>Once a malicious actor has access to a legitimate user's keypair, the attacks are again quite simple. Keys form the backbone of our system's authentication mechanism, and a stolen keypair enables the complete impersonation of a user. This would allow an attacker to access, modify, and delete files in that user's groups – breaking confidentiality and integrity assumptions. In addition, it may be possible to perform “internal DoS attacks”. These could be characterized by creating many groups, or sending many requests as an already authenticated user in an attempt to overwhelm the group server. They also could fill the File Server with garbage data files, filling its storage capacity and preventing legitimate groups from storing new files.</p>
  <p>Again, the crux of this threat is that it enables an attacker to perform these actions <em>while being a properly authenticated entity.</em> By impersonating a legitimate user, it becomes much harder for many potential DoS prevention mechanisms to filter out malicious requests from legitimate ones.</p>

  <h3>Countermeasures:</h3>
  <p>A multiple key policy is the basis of our proposed solution to the key compromise threat. With multiple keys, users are able to more easily revoke and rotate their keys intermittently. It also means that an attacker will have to expend much more effort to steal information that could lock a user out of their account. This is due to a privilege escalation policy, that may be implemented by two different mechanisms: the Administrative Key mechanism and the Key Quorum mechanism. Each provides a policy of privilege escalation for critical account management tasks – namely key addition and revocation.</p>
  <p>First we look at the Administrative Key mechanism. In a system implementing this, each user designates a key that is expected to be kept more secure than a normal user key. When making a request for administrative action, the user will engage in the protocol illustrated here.</p>

  <img src = "AdminKey.png" alt="Administrative User Key Protocol" style="width:879px;height:552px;">

  <p>Only a single message must be sent to the Group Server after initiating the request. It is assumed here that the user has already authenticated themselves and has a mutually agreed upon session key and HMAC key. The structure of the addition certificate itself is necessarily small, as it must be signed by a 3072 bit RSA key. Therefore, it is simply the text “ADDCERT” concatenated with the SHA-256 fingerprint of the key the user wishes to add; or “REVCERT” for a user wishing to revoke a key. This means it is easy for a user to generate addition and revocation certificates, and the Group Server does not need to keep a record of issuing certificates or be involved in their distribution to clients. One of the major drawbacks of the Administrative Key approach is the single point of attack for a malicious entity. The Administrative Key itself represents a very high value target, and one which will be able to override the true user's authority if it is stolen. </p>
  <p>Key Quorum administration operates under the assumption of a user having a set of keys which they use in different situations, and on different devices. This means it is unlikely that an attacker will get a large amount of key material, yet the user should be able to collect their keys in the event of needing to take administrative action. This approach may be advantageous in a scenario where an organization issues hardware tokens containing user keys. This makes it more psychologically acceptable to keep them physically separated, and humans are more used to keeping items physically secure than data.</p>
  <p>The principles of the Key Quorum method are similar to that of the Administrative Key. In fact, it provides the same policy of account administration, but instead of relying on a single high-privilege key; the privilege requires a critical mass of keys at once. Let us examine a particular scenario, where the “Quorum number” is 3, and the user has 5 keys used for several different usage scenarios. Let us further assume that an attacker has managed to steal one key – and thereby deprive the user of it. This malicious entity will be able to properly authenticate with the group server and use the file server in malicious ways. However, they will not be able to perform administrative actions on the account. They will not be permitted to add keys of their own, and they will not be permitted to revoke the already approved keys of the user. The user however, upon noticing this theft, will simply gather three of their keys, authenticate with the Group Server, request key revocation and engage in the protocol illustrated here.</p>

  <img src="KeyQuorum.png" alt="Key Quorum Administrative Protocol" style="width:879px;height:552px;">

  <p>The Group Server need only verify several levels of keys (in the correct specified order) in order to verify the request as a whole, and it will then revoke the compromised key. The Group Server's verification process will proceed by matching the given keys to those it has associated with the user (if it can). It does not directly use the provided keys to verify the signatures on the certificate. After revocation has completed, the user may then generate a new key to replace the stolen one, and the attacker will have only gained transient access to the system. With appropriate logging mechanisms, any changes made by the malicious user could be easily noticed and reverted, and normal operation could resume after only a small inconvenience.</p>
  <p>An important parameter to select is the Quorum number. This should be high enough so that a malicious entity will be hard-pressed to steal a critical number of keys, yet low enough to not be overly cumbersome for the user. It should also depend on how many keys that user has attached to their account. This method could also provide a feedback loop of difficulty for the user, so that adding a new key becomes harder the more keys they have already added. This can be in turn be tuned in a practical situation to prevent a user having too many keys to keep track of, leading to a more trivial task of an attacker to steal them. However this does not also preclude the option of introducing a hard limit for the number of keys, which would also be effective in preventing "key inflation"</p>
  

<!-- END CHANGES HERE -->
    </section>
    <section id="discussion">
      <h2>Discussion</h2>
<!-- BEGIN CHANGES HERE -->

<p>The key compromise threat model is a realistic threat in the case of a file-sharing system where users are responsible for their key management. While key-based authentication methods are easy for experienced users, they may prove daunting for novice users, or those not well versed in privacy methods. Users would be responsible for their own key revocation in particular, which requires them to be vigilant of who may be using their account other than themselves.</p>

<p>As designers, we should realize that information leakage would lead to problematic situations, like compromised private key, loss of secret shared in the files, and the broken forward scerecy described already. The system should protect users's information and provide methods to encrypt all the important files automatically and also provide the perfect forward secrecy.</p>

<p>Nothing in this phase changes the defences accomplished through threats 1-7. The only thing related to denfences achieved in previous phases is that we changed our authentication protocol from using RSA keypairs to signed Diffie-Hellman key exchange. The authentication can still be achieved by verifying the signature of D-H public keys. The two sides exchange the shared secret key generated from information exhanged with a different algorithm instead of encrypting a generated key and sending that direcly to the other side. However, no matter of what method is used, a secret key is exchanged to protect the ongoing communication. Furthermore, the identity key to calculate the hmac value and the nonce to keep tracking of order will be exchanged after the shared key exchanged in the new protocol. Even though they're transmitted in a diffent way compared to the previous protocol, the identity of the communications and the order of messages can still be obtained with that identity key and nonce.</p>

<p>We have implemented the countermeasures for "the information leakage from disks" and "broken forward secrecy". For the first one, we used the algorithem PBKDF2WithHmacSHA1 to derive an AES key from self-defined password to encrypt files and private keys. Everytime the user/server needs to enter the password to start the program. That entered password would be used to calculate the AES key and decrypt all the information they need. When the information needs to be saved back to the disk, the derived key will encrypt the files and store them. This is secure because our assumption is that the adversary can only get a copy of disk image without any real-time data. For the second threat, we replaced our previous authentication and key exchange protocol with Signed Diffie-Hellman protocol for both group server and file server.</p>

<!-- END CHANGES HERE -->
    </section>
  </body>
</html>
