using IdentityServer_BE.Data;
using IdentityServer_BE.Helpers;
using IdentityServer_BE.Models;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using System.Security.Claims;

namespace IdentityServer_BE.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<User> _userManager;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IEmailService _emailService;
        private readonly JwtHelper _jwtHelper;
        private readonly OtpHelper _otpHelper;
        private readonly IConfiguration _configuration;

        public AuthService(
            UserManager<User> userManager,
            IUnitOfWork unitOfWork,
            IEmailService emailService,
            JwtHelper jwtHelper,
            OtpHelper otpHelper,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _unitOfWork = unitOfWork;
            _emailService = emailService;
            _jwtHelper = jwtHelper;
            _otpHelper = otpHelper;
            _configuration = configuration;
        }

        public async Task<string> RegisterAsync(RegisterModel model)
        {
            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
                return "Email is already in use.";

            var user = new User
            {
                UserName = model.Email,
                Email = model.Email,
                PhoneNumber = model.PhoneNumber,
                Address = model.Address,
                Status = "Active",
                Role = "User"
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = $"http://localhost:3000/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";
                await _emailService.SendEmailAsync(user.Email, "Confirm your email", $"Click <a href='{confirmationLink}'>here</a> to confirm your email.");
                await _unitOfWork.SaveChangesAsync();
                return "Registration successful. Please check your email to confirm.";
            }
            return string.Join(", ", result.Errors.Select(e => e.Description));
        }

        public async Task<string> LoginAsync(LoginModel model, bool isExternalLogin = false)
        {
            var user = await _unitOfWork.UserRepository.FindByEmailAsync(model.Email);
            if (user == null)
                return "Invalid credentials";

            if (!isExternalLogin && !await _userManager.CheckPasswordAsync(user, model.Password))
                return "Invalid credentials";

            if (!await _userManager.IsEmailConfirmedAsync(user))
                return "Email not confirmed";

            if (user.Status != "Active")
                return "Account is inactive or locked";

            if (!string.IsNullOrEmpty(model.TwoFactorCode))
            {
                var twoFactorModel = new TwoFactorModel { UserId = user.Id, Code = model.TwoFactorCode };
                if (!await Verify2FACodeAsync(twoFactorModel))
                    return "Invalid 2FA code";
            }

            var token = _jwtHelper.GenerateJwtToken(user);
            await _unitOfWork.SaveChangesAsync();
            return token;
        }

        public async Task<string> UpdateProfileAsync(string userId, UpdateProfileModel model)
        {
            var user = await _unitOfWork.UserRepository.FindByIdAsync(userId);
            if (user == null) return "User not found";

            user.PhoneNumber = model.PhoneNumber;
            user.AvatarUrl = model.AvatarUrl;

            if (!string.IsNullOrEmpty(user.PhoneNumber) && !new System.ComponentModel.DataAnnotations.PhoneAttribute().IsValid(user.PhoneNumber))
                return "Invalid phone number format";

            if (!string.IsNullOrEmpty(user.AvatarUrl) && !new System.ComponentModel.DataAnnotations.UrlAttribute().IsValid(user.AvatarUrl))
                return "Invalid URL format for avatar";

            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
            {
                await _unitOfWork.SaveChangesAsync();
                return "Profile updated successfully";
            }
            return string.Join(", ", result.Errors.Select(e => e.Description));
        }

        public async Task<string> Generate2FACodeAsync(string userId)
        {
            var user = await _unitOfWork.UserRepository.FindByIdAsync(userId);
            if (user == null) return "User not found";

            var code = _otpHelper.GenerateOtpCode();
            await _userManager.SetTwoFactorEnabledAsync(user, true);
            await _emailService.SendEmailAsync(user.Email, "Your 2FA Code", $"Your 2FA code is: {code}");
            await _unitOfWork.SaveChangesAsync();
            return "2FA code sent to your email.";
        }

        public async Task<bool> Verify2FACodeAsync(TwoFactorModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null) return false;

            return _otpHelper.VerifyOtpCode(model.Code);
        }

        public async Task<string> ForgotPasswordAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return "User not found";

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = $"http://localhost:3000/reset-password?email={user.Email}&token={Uri.EscapeDataString(token)}";
            await _emailService.SendEmailAsync(user.Email, "Reset your password", $"Click <a href='{resetLink}'>here</a> to reset your password.");
            return "Password reset link sent to your email.";
        }

        public async Task<string> ResetPasswordAsync(ResetPasswordModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null) return "User not found";

            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (result.Succeeded)
            {
                await _unitOfWork.SaveChangesAsync();
                return "Password reset successful.";
            }
            return string.Join(", ", result.Errors.Select(e => e.Description));
        }

        public async Task<string> ChangePasswordAsync(string userId, ChangePasswordModel model)
        {
            var user = await _unitOfWork.UserRepository.FindByIdAsync(userId);
            if (user == null)
                return "User not found";

            // Verify current password
            if (!await _userManager.CheckPasswordAsync(user, model.CurrentPassword))
                return "Current password is incorrect";

            // Change to new password
            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);

            if (result.Succeeded)
            {
                await _unitOfWork.SaveChangesAsync();

                // Optional: Send notification email
                await _emailService.SendEmailAsync(
                    user.Email,
                    "Password Changed",
                    "Your password has been successfully changed.");

                return "Password changed successfully";
            }

            return string.Join(", ", result.Errors.Select(e => e.Description));
        }
    }
}