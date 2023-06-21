
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Challenge36 {

    public static void main(String[] args) {
        printTitle(5, 36);

        SecureRandom rand = new SecureRandom();
        BigInteger N = new BigInteger("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16);

        BigInteger g = BigInteger.valueOf(2);
        BigInteger k = BigInteger.valueOf(3);

        // part 1: save password
        String I = "foo@bar.com";
        String P = "sup3r s3cr3t";
        PasswordStore store = savePassword(g, N, I, P);

        // part 2: start authentication
        BigInteger a = new BigInteger(N.bitLength(), rand).mod(N);
        BigInteger A = g.modPow(a, N);
        byte[] salt = authStep1(store, I, N, g, k);

        // Client computes K
        MessageDigest sha = getSHA256Instance();
        sha.update(A.toByteArray());
        sha.update(store.B.toByteArray());
        byte[] uH = sha.digest();
        BigInteger u = new BigInteger(1, uH);

        sha.reset();
        sha.update(salt);
        sha.update(P.getBytes());
        byte[] xH = sha.digest();
        BigInteger x = new BigInteger(1, xH);

        BigInteger S = store.v.modPow(u, N).multiply(A).modPow(store.b, N);

        sha.reset();
        sha.update(S.toByteArray());
        byte[] KH = sha.digest();

        byte[] K = Arrays.copyOf(KH, 32);

        // Client sends hmac
        byte[] proof = utils.HmacSha256(K, salt);
        boolean res = authStep2(store, A, N, proof);
        System.out.println(res);
        System.out.println();
    }

    public static void printTitle(int set, int challenge) {
        System.out.println("Set " + set + " - Challenge " + challenge + "\n");
    }

    public static class PasswordStore {
        String I;
        byte[] salt;
        BigInteger v;
        BigInteger b;
        BigInteger B;
        BigInteger u;

        public PasswordStore(String I, byte[] salt, BigInteger v, BigInteger b, BigInteger B, BigInteger u) {
            this.I = I;
            this.salt = salt;
            this.v = v;
            this.b = b;
            this.B = B;
            this.u = u;
        }
    }

    public static PasswordStore savePassword(BigInteger g, BigInteger N, String I, String P) {
        SecureRandom rand = new SecureRandom();
        byte[] salt = new byte[4];
        rand.nextBytes(salt);

        MessageDigest sha = getSHA256Instance();
        sha.update(salt);
        sha.update(P.getBytes());
        byte[] xH = sha.digest();
        BigInteger x = new BigInteger(1, xH);
        BigInteger v = g.modPow(x, N);

        return new PasswordStore(I, salt, v, null, null, null);
    }

    public static byte[] authStep1(PasswordStore store, String I, BigInteger N, BigInteger g, BigInteger k) {
        if (!store.I.equals(I)) {
            throw new IllegalArgumentException("Invalid identity");
        }

        SecureRandom rand = new SecureRandom();
        BigInteger b = new BigInteger(N.bitLength(), rand).mod(N);
        BigInteger B = g.modPow(b, N).add(k.multiply(store.v)).mod(N);

        byte[] salt = store.salt;

        store.b = b;
        store.B = B;

        return salt;
    }

    public static boolean authStep2(PasswordStore store, BigInteger A, BigInteger N, byte[] proof) {
        MessageDigest sha = getSHA256Instance();
        sha.update(A.toByteArray());
        sha.update(store.B.toByteArray());
        byte[] uH = sha.digest();
        BigInteger u = new BigInteger(1, uH);

        BigInteger S = store.v.modPow(u, N).multiply(A).modPow(store.b, N);

        sha.reset();
        sha.update(S.toByteArray());
        byte[] KH = sha.digest();

        byte[] K = Arrays.copyOf(KH, 32);

        sha.reset();
        sha.update(K);
        sha.update(store.salt);
        byte[] expectedProof = sha.digest();

        return Arrays.equals(expectedProof, proof);
    }

    public static MessageDigest getSHA256Instance() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found");
        }
    }
}
