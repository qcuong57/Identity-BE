using IdentityServer_BE.Models;
using System.Threading.Tasks;

namespace IdentityServer_BE.Services
{
    public interface IAuthService
    {
        Task<string> RegisterAsync(RegisterModel model);
        Task<string> LoginAsync(LoginModel model, bool isExternalLogin = false);
        Task<string> UpdateProfileAsync(string userId, UpdateProfileModel model);
        Task<string> GenerateTokenAsync(User user);
        Task<string> Generate2FACodeAsync(string userId);
        Task<bool> Verify2FACodeAsync(TwoFactorModel model);
        Task<string> ForgotPasswordAsync(string email);
        Task<string> ResetPasswordAsync(ResetPasswordModel model);
        Task<string> ChangePasswordAsync(string userId, ChangePasswordModel model);
        Task<bool> Is2FAEnabledAsync(string userId);
        Task<string> Disable2FAAsync(string userId);
        Task<string> ResendVerificationAsync(ResendVerificationModel model);
    }
}