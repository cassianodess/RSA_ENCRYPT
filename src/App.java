public class App {
    public static void main(String[] args) throws Exception {
        RSA rsa = new RSA();
        String encryptedMessage = rsa.encrypt("Cassiano");
        System.out.println(rsa.decrypt(encryptedMessage));
    }
}
