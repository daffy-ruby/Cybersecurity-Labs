import pyotp
import qrcode

class GoogleAuthenticatorManager:
    def __init__(self, issuer_name="SecureAuthSystem"):
        self.issuer_name = issuer_name

    def generate_user_secret(self):
        """Generates a unique Base32 secret string for a new user."""
        return pyotp.random_base32()

    def get_setup_qr(self, username, secret, save_filename=None):
        """Generates standard otpauth:// URI and exports setup QR code."""
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=username, issuer_name=self.issuer_name)

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        if save_filename:
            img.save(save_filename)
            print(f"[TOTP SETUP] QR Code saved to file: {save_filename}")

        return provisioning_uri

    def verify_code(self, secret, input_code):
        """Verifies 6-digit code against secret with a 30-second leeway window."""
        totp = pyotp.TOTP(secret)
        return totp.verify(input_code, valid_window=1)