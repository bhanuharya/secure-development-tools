// The stored PIN is decoded back to clear text to compare it.
public class RecoverablePassword {
    public boolean verifyPin(Account account, String pin) {
        return account.getPwd() != null && PasswordCodec.decode(account.getPwd()).equals(pin);
    }
}
