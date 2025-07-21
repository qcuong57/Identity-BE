using System.Security.Cryptography;
using IdentityServer_BE.Models;

namespace IdentityServer_BE.Helpers
{
    public class OtpHelper
    {
        private const int OTP_LENGTH = 6;
        private const int MAX_ATTEMPTS = 5;
        private const int LOCKOUT_MINUTES = 15;

        public string GenerateOtpCode()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] bytes = new byte[4];
                rng.GetBytes(bytes);
                int value = Math.Abs(BitConverter.ToInt32(bytes, 0));
                return (value % 1000000).ToString("D6");
            }
        }

        public string HashOtpCode(string otpCode)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hashedBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(otpCode));
                return Convert.ToBase64String(hashedBytes);
            }
        }

        public bool VerifyOtpCode(string inputCode, string hashedCode)
        {
            if (string.IsNullOrEmpty(inputCode) || string.IsNullOrEmpty(hashedCode))
                return false;

            string hashedInput = HashOtpCode(inputCode);
            return hashedInput == hashedCode;
        }

        public bool IsOtpExpired(DateTime? expiryTime)
        {
            return !expiryTime.HasValue || DateTime.UtcNow > expiryTime.Value;
        }

        public bool IsUserLockedOut(User user)
        {
            return user.OtpLockoutTime.HasValue && DateTime.UtcNow < user.OtpLockoutTime.Value;
        }

        public void IncrementFailedAttempts(User user)
        {
            user.OtpAttempts++;
            
            if (user.OtpAttempts >= MAX_ATTEMPTS)
            {
                user.OtpLockoutTime = DateTime.UtcNow.AddMinutes(LOCKOUT_MINUTES);
            }
        }

        public void ResetFailedAttempts(User user)
        {
            user.OtpAttempts = 0;
            user.OtpLockoutTime = null;
        }

        public DateTime GetOtpExpiry()
        {
            return DateTime.UtcNow.AddMinutes(5); // OTP có hiệu lực trong 5 phút
        }
    }
}