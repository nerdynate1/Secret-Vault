import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.util.Tuple;
import java.io.Console;

public class SecretVaultCLI {
    public static void main(String[] args) throws Exception {
        Console console = System.console();
        if (console == null) {
            System.err.println("Error: No console available");
            System.exit(1);
        }

        char[] passwordChars = console.readPassword("Vault Password: ");
        String password = new String(passwordChars);
        if (password.length() < 7) {
            System.err.println("Error: Vault password must be at least 7 characters.");
            System.exit(1);
        }

        java.util.Arrays.fill(passwordChars, ' ');
        OptionParser parser = new OptionParser(args);
        parser.setOptString("as:u:k:g:pr:");
        LongOption[] longOpts = {
            new LongOption("add", false, 'a'),
            new LongOption("service", true, 's'),
            new LongOption("user", true, 'u'),
            new LongOption("key", true, 'k'),
            new LongOption("keygen", false, 'c'),
            new LongOption("gen", true, 'g'),
            new LongOption("lookup-pass", false, 'p'),
            new LongOption("lookup-key", false, 'r')
        };

        parser.setLongOpts(longOpts);
        String service = null;
        String user = null;
        String key = null;
        int genLength = -1;
        boolean keygen = false;
        boolean lookupPass = false;
        boolean lookupKey = false;
        Tuple<Character, String> opt;
        while ((opt = parser.getLongOpt(false)) != null) {
            switch (opt.getFirst()) {
                case 'a': break;
                case 's': service = opt.getSecond(); break;
                case 'u': user = opt.getSecond(); break;
                case 'k': key = opt.getSecond(); break;
                case 'g': genLength = Integer.parseInt(opt.getSecond()); break;
                case 'c': keygen = true; break;
                case 'p': lookupPass = true; break;
                case 'r': lookupKey = true; break;
                case '?': printUsageAndExit();
            }
        }

        String[] nonOpts = parser.getNonOpts();
        SecretVault vault = new SecretVault();
        vault.createVault(password);
        if (lookupPass) {
            handleLookupPass(vault, nonOpts);
        } else if (lookupKey) {
            handleLookupKey(vault, nonOpts);
        } else if (keygen) {
            handleKeyGen(vault, service);
        } else if (genLength > 0) {
            handleGenPassword(vault, console, service, user, genLength);
        } else if (key != null) {
            handleAddKey(vault, service, key);
        } else if (user != null) {
            handleAddUser(vault, console, service, user);
        } else {
            printUsageAndExit();
        }

        vault.saveVault();
        System.out.println("Vault updated successfully");
    }

    private static void handleLookupPass(SecretVault vault, String[] nonOpts) throws Exception {
        if (nonOpts.length == 0) errorExit("Missing service name");
        String[] creds = vault.getCredentials(nonOpts[0]);
        if (creds == null) {
            System.out.println("No credentials found");
        } else {
            System.out.println("UserName: " + creds[0]);
            System.out.println("Password: " + creds[1]);
        }
    }

    private static void handleLookupKey(SecretVault vault, String[] nonOpts) throws Exception {
        if (nonOpts.length == 0) errorExit("Missing service name");
        String key = vault.getPrivateKey(nonOpts[0]);
        if (key == null) {
            System.out.println("No private key found");
        } else {
            System.out.println("Private Key (Base64):");
            System.out.println(key.replaceAll("(.{64})", "$1\n"));
        }
    }

    private static void handleKeyGen(SecretVault vault, String service) throws Exception {
        if (service == null) errorExit("--service required");
        vault.addServiceWithPrivateKey(service);
    }

    private static void handleGenPassword(SecretVault vault, Console console, String service, String user, int length) throws Exception {
        if (service == null || user == null) errorExit("--service and --user required");
        if (length < 7) System.out.println("Warning: Password length < 7 is insecure");
        vault.addAccountWithRandomPassword(service, user, length);
    }

    private static void handleAddKey(SecretVault vault, String service, String key) throws Exception {
        if (service == null) errorExit("--service required");
        vault.addServiceWithKey(service, key);
    }

    private static void handleAddUser(SecretVault vault, Console console, String service, String user) throws Exception {
        if (service == null || user == null) errorExit("--service and --user required");
        char[] password = console.readPassword("Service Password: ");
        if (password.length == 0) errorExit("Password cannot be empty");
        if (password.length < 7) System.out.println("Warning: Password length < 7 is insecure");
        vault.addAccount(service, user, new String(password));
    }

    private static void printUsageAndExit() {
        printUsage();
        System.exit(1);
    }

    private static void errorExit(String message) {
        System.err.println("Error: " + message);
        System.exit(1);
    }

    private static void printUsage() {
        System.err.println("Usage:");
        System.err.println("secrets --add --service <name> --user <uname>");
        System.err.println("secrets --add --service <name> --user <uname> --gen <len>");
        System.err.println("secrets --add --service <name> --key <key>");
        System.err.println("secrets --add --service <name> --keygen");
        System.err.println("secrets --lookup-pass <name>");
        System.err.println("secrets --lookup-key <name>");
    }
}