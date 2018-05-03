package tn.esprit.securite;
import com.google.common.io.BaseEncoding;



import com.google.common.primitives.Bytes;


import javabc.SecureRandom;
import com.codename1.util.Base64;
import org.bouncycastle.crypto.digests.SHA512Digest;
        


/**
 * FOSJCrypt fait le hachage et le cryptage comme le FOSUser(default encoder:Sha512) via application desktop Java.
 * La génération de salt et comme de FOSUser
 * La génération de hash et celle que FOSUser 5000 itération sur digester (une avant le boucle pour fusionner le salt avec le password) and ajout les accolades
 * Conversion
 * Google Guava utiliser pour convertir le hash en base64 (password column FOSUser contient hash convertit en base64 par cette API
 * Cette API utilise le même Algorithm par défaut utiliser par FOSUser(voir security.yml encoders{algorithm})
 * @author Zain ELabidine membre de " The Optimists"
 * @Email: zainelabidine.bensaleh@esprit.tn
 *Api à télécharger:
 * 1) guava-19.0.jar
 * 2) commons-codec-1.7.jar
 *
 */
public class FOSJCrypt {
    private static final String ALGORITHM = "SHA-512";
    private static final int ITERATIONS = 5000;
    private static final int SALT_SIZE = 32;


    /**
     * Private constructor.
     */
    private FOSJCrypt() {
    }
    public static Sha512 crypt(String clairPass) {
        String gs=generateSalt();
        //System.out.println(gs);
        try {
            
            byte[] hash = encodePassword(clairPass, gs);
            
            return passwordToPersist(hash, clairPass, gs);
        } catch (Exception  ex) {
            System.out.println("++++++++"+ex.getMessage());
        }
        return null;
    }

    /**
     * tgeneri salt kif al yasn3ou fosuser(bel algorrithm par défaut :sh512)
     * igeneri 32 byte et y7awelhom en base64
     * ibadel el + bel .
     * ine7i el char el le5er
     * @return
     */
    private static String generateSalt() {       
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);
        String saltBase64_encoded=BaseEncoding.base64().encode(salt);
        String saltPlusDot= saltBase64_encoded.replace('+','.');
        return saltPlusDot.substring(0,saltPlusDot.length()-1);
    }

    /**
     * 4999 itération dans la boucles une seul avant la boucle
     * 1ére : fait merge passwrd et sal par méthode
     * dans la boucle il réutilise le hash précédant pour générer le nouveau message en clair
     * @param password
     * @param salt
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    private static byte[] encodePassword(String password,String salt) throws Exception
             {                 
        String mergedPasswordAndSalt =mergePasswordAndSalt(password, salt);
        SHA512Digest digester =new  SHA512Digest();
        byte[] hash=mergedPasswordAndSalt.getBytes("UTF-8");
                 System.out.println("1)"+Base64.encodeNoNewline(hash));
        digester.doFinal(hash,0);
        System.out.println("first iteration"+Base64.encodeNoNewline(hash));
        for (int i = 1; i < ITERATIONS; ++i) {           
            digester.doFinal(Bytes.concat(hash, mergedPasswordAndSalt.getBytes("UTF-8")),0);
        }      
        //System.out.println("after encode final"+Base64.encodeNoNewline(hash));
        return hash;
    }

    /**
     * i7ot des accolade mnloul welle5er mta3 salt
     * @param pass
     * @param salt
     * @return
     */
    private static String mergePasswordAndSalt(String pass, String salt) {
        if (salt == null) {
            return salt;
        }
        String cg="{";String cd="}";
        return pass+cg+salt+cd;
    }
    /*
     *  paramétre: originalHash el hash ala mel base de donnés mais en byte donc lazem el hash ala en String tetbadel bytes
     */
    public static   boolean verifyPassword(byte[] originalHash, String passwordClair, String salt) throws
            Exception {
        byte[] comparisonHash = encodePassword(passwordClair, salt);
        return comparePasswords(originalHash, comparisonHash);
    }
    private static Sha512 passwordToPersist(byte[] originalHash, String password, String salt) throws
            Exception  {
        Sha512 sh=new Sha512();
        sh.setSalt(salt);sh.setHash(BaseEncoding.base64().encode(originalHash));
        
        return sh;
    }
    private static boolean comparePasswords(byte[] originalHash, byte[] comparisonHash) {
        int diff = originalHash.length ^ comparisonHash.length;
        for (int i = 0; i < originalHash.length && i < comparisonHash.length; i++) {
            diff |= originalHash[i] ^ comparisonHash[i];
        }

        return diff == 0;
    }

    public static boolean checkPassword(String originalHashStr, String passwordClair,String salt) throws Exception  {
        byte[] comparisonHash = encodePassword(passwordClair, salt);    
        byte[] originalHash = Base64.decode(originalHashStr.getBytes("UTF-8"));
        return comparePasswords(originalHash, comparisonHash);
    }
}
