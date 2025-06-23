using OtpNet;

namespace IdentityServer_BE.Helpers
{
    public class OtpHelper
    {
        private readonly string _secretKey;

        public OtpHelper(IConfiguration configuration)
        {
            _secretKey = configuration["TwoFactor:SecretKey"] ?? Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
        }

        public string GenerateOtpCode()
        {
            var totp = new Totp(Base32Encoding.ToBytes(_secretKey));
            return totp.ComputeTotp();
        }

        public bool VerifyOtpCode(string code)
        {
            var totp = new Totp(Base32Encoding.ToBytes(_secretKey));
            return totp.VerifyTotp(code, out _, new VerificationWindow(previous: 1, future: 1));
        }
    }
}