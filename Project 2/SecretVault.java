import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.JsonIO;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

public class SecretVault {
    private static final int gcmLength = 128; 
    private static final int cost = 2048;
    private static final int blockSize = 8;
    private static final int parallelization = 1;
    private static final String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789#$%!&*@?";

    private JSONObject vaultJson;
    private byte[] vaultKey;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public SecretVault() {
        this.vaultJson = new JSONObject();
    }

    public void createVault(String password) throws Exception {
        if (!Files.exists(Paths.get("vault.json"))) {
            byte[] salt = generateRandomBytes(16);
            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            vaultJson.put("salt", saltBase64);

            byte[] rootKey = deriveKey(password, salt);
            byte[] vaultKeyBytes = generateRandomBytes(32);
            this.vaultKey = vaultKeyBytes;

            byte[] iv = generateRandomBytes(12);
            String ivBase64 = Base64.getEncoder().encodeToString(iv);
            String encryptedVaultKey = encrypt(Base64.getEncoder().encodeToString(vaultKeyBytes), rootKey, iv);

            JSONObject vaultKeyJson = new JSONObject();
            vaultKeyJson.put("iv", ivBase64);
            vaultKeyJson.put("key", encryptedVaultKey);
            vaultJson.put("vaultkey", vaultKeyJson);

            vaultJson.put("passwords", new JSONArray());
            vaultJson.put("privkeys", new JSONArray());

            saveVault();
        } else {
            loadVault(password);
        }
    }

    private void loadVault(String password) throws Exception {
        File jsonFile = new File("vault.json");
        if (!jsonFile.exists()) {
            throw new FileNotFoundException("vault.json not found.");
        }
    
        try {
            vaultJson = JsonIO.readObject(jsonFile);
    
            if (!vaultJson.containsKey("salt") || !vaultJson.containsKey("vaultkey")) {
                throw new Exception("Invalid or corrupted vault file.");
            }
    
            String saltBase64 = vaultJson.getString("salt");
            byte[] salt = Base64.getDecoder().decode(saltBase64);
            byte[] rootKey = deriveKey(password, salt);
    
            JSONObject vaultKeyJson = vaultJson.getObject("vaultkey");
            String ivBase64 = vaultKeyJson.getString("iv");
            String encryptedVaultKey = vaultKeyJson.getString("key");
    
            byte[] iv = Base64.getDecoder().decode(ivBase64);
            String decryptedVaultKey = decrypt(encryptedVaultKey, rootKey, iv);
            this.vaultKey = Base64.getDecoder().decode(decryptedVaultKey);
    
        } catch (Exception e) {
            throw new Exception("Failed to unseal vault. Incorrect password?", e);
        }
    }

    public void saveVault() throws Exception {
        try (FileWriter writer = new FileWriter("vault.json")) {
            writer.write(vaultJson.toJSON());
        }
    }

    public void addAccount(String service, String user, String password) throws Exception {
        if (service == null || service.isEmpty()) throw new IllegalArgumentException("Service is required.");
        if (user == null || user.isEmpty()) throw new IllegalArgumentException("Username is required.");
        if (password == null || password.isEmpty()) throw new IllegalArgumentException("Password is required.");

        byte[] iv = generateRandomBytes(12);
        String ivBase64 = Base64.getEncoder().encodeToString(iv);
        String encryptedPassword = encrypt(password, vaultKey, iv, service, user);

        JSONObject account = new JSONObject();
        account.put("iv", ivBase64);
        account.put("service", service);
        account.put("user", user);
        account.put("pass", encryptedPassword);
        
        vaultJson.getArray("passwords").add(account);
    }

    public void addAccountWithRandomPassword(String service, String user, int passwordLength) throws Exception {
        if (passwordLength <= 0) throw new IllegalArgumentException("Password is invalid.");
        if (service == null || service.isEmpty()) throw new IllegalArgumentException("Service is required");
        if (user == null || user.isEmpty()) throw new IllegalArgumentException("Username is required");

        String password = generateRandomPassword(passwordLength);
        addAccount(service, user, password);
    }

    public String[] getCredentials(String service) throws Exception {
        JSONArray passwords = vaultJson.getArray("passwords");
        for (int i = 0; i < passwords.size(); i++) {
            JSONObject account = passwords.getObject(i);
            String storedService = account.getString("service");
            if (storedService.equals(service)) {
                String ivBase64 = account.getString("iv");
                String encryptedPass = account.getString("pass");
                String user = account.getString("user");
                byte[] iv = Base64.getDecoder().decode(ivBase64);
                String password = decrypt(encryptedPass, vaultKey, iv, service, user);
                return new String[]{user, password};
            }
        }
        return null;
    }

    public void addServiceWithKey(String service, String key) throws Exception {
        byte[] iv = generateRandomBytes(12);
        String ivBase64 = Base64.getEncoder().encodeToString(iv);
        String encryptedKey = encrypt(key, vaultKey, iv, service, "");
        JSONObject keyAccount = new JSONObject();
        keyAccount.put("iv", ivBase64);
        keyAccount.put("service", service);
        keyAccount.put("private key", encryptedKey);
        vaultJson.getArray("private keys").add(keyAccount);
    }

    public void addServiceWithPrivateKey(String service) throws Exception {
        KeyPair keyPair = generateElGamalKeyPair();
        ElGamalPrivateKey privateKey = (ElGamalPrivateKey) keyPair.getPrivate();
        @SuppressWarnings("deprecation")
        ElGamalPublicKey publicKey = (ElGamalPublicKey) keyPair.getPublic();
        
        System.out.println("Public Key: ");
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        
        addServiceWithKey(service, Base64.getEncoder().encodeToString(privateKey.getEncoded()));
    }

    public String getPrivateKey(String service) throws Exception {
        JSONArray privkeys = vaultJson.getArray("private keys: ");
        for (int i = 0; i < privkeys.size(); i++) {
            JSONObject keyAccount = privkeys.getObject(i);
            if (keyAccount.getString("service").equals(service)) {
                String ivBase64 = keyAccount.getString("iv");
                String encryptedKey = keyAccount.getString("private key");
                byte[] iv = Base64.getDecoder().decode(ivBase64);
                return decrypt(encryptedKey, vaultKey, iv, service, "");
            }
        }
        return null;
    }

    private String encrypt(String data, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(gcmLength, iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String encrypt(String data, byte[] key, byte[] iv, String service, String user) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(gcmLength, iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
        cipher.updateAAD(service.getBytes(StandardCharsets.UTF_8));
        cipher.updateAAD(user.getBytes(StandardCharsets.UTF_8));
        byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String decrypt(String encryptedData, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(gcmLength, iv);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private String decrypt(String encryptedData, byte[] key, byte[] iv, String service, String user) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(gcmLength, iv);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
        cipher.updateAAD(service.getBytes(StandardCharsets.UTF_8));
        cipher.updateAAD(user.getBytes(StandardCharsets.UTF_8));
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private byte[] deriveKey(String password, byte[] salt) {
        return SCrypt.generate(
            password.getBytes(StandardCharsets.UTF_8), salt, cost, blockSize, parallelization, 32);
    }

    private String generateRandomPassword(int length) {
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();
        for (int i = 0; i < length; i++) {
            password.append(characters.charAt(random.nextInt(characters.length())));
        }
        return password.toString();
    }

    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private KeyPair generateElGamalKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", "BC");
        keyGen.initialize(512, new SecureRandom());
        return keyGen.generateKeyPair();
    }
}