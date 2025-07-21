using IdentityServer_BE.Data;
using IdentityServer_BE.Helpers;
using IdentityServer_BE.Models;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Text.RegularExpressions;

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
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            UserManager<User> userManager,
            IUnitOfWork unitOfWork,
            IEmailService emailService,
            JwtHelper jwtHelper,
            OtpHelper otpHelper,
            IConfiguration configuration,
            ILogger<AuthService> logger)
        {
            _userManager = userManager;
            _unitOfWork = unitOfWork;
            _emailService = emailService;
            _jwtHelper = jwtHelper;
            _otpHelper = otpHelper;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task<string> GenerateTokenAsync(User user)
        {
            try
            {
                return _jwtHelper.GenerateJwtToken(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating token for user {UserId}", user.Id);
                return null;
            }
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
                var confirmationLink =
                    $"http://localhost:3000/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";
                await _emailService.SendEmailAsync(user.Email, "Confirm your email",
                    $"Click <a href='{confirmationLink}'>here</a> to confirm your email.");
                await _unitOfWork.SaveChangesAsync();
                return "Registration successful. Please check your email to confirm.";
            }

            return string.Join(", ", result.Errors.Select(e => e.Description));
        }

        public async Task<string> LoginAsync(LoginModel model, bool isExternalLogin = false)
        {
            try
            {
                var user = await _unitOfWork.UserRepository.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    _logger.LogWarning("Login attempt with non-existent email: {Email}", model.Email);
                    return "Invalid credentials";
                }

                if (!isExternalLogin && !await _userManager.CheckPasswordAsync(user, model.Password))
                {
                    _logger.LogWarning("Invalid password for user: {Email}", model.Email);
                    return "Invalid credentials";
                }

                if (!await _userManager.IsEmailConfirmedAsync(user))
                {
                    _logger.LogWarning("Email not confirmed for user: {Email}", model.Email);
                    return "Email not confirmed";
                }

                if (user.Status != "Active")
                {
                    _logger.LogWarning("Inactive account login attempt: {Email}", model.Email);
                    return "Account is inactive or locked";
                }

                if (await _userManager.GetTwoFactorEnabledAsync(user))
                {
                    if (string.IsNullOrEmpty(model.TwoFactorCode))
                    {
                        await Generate2FACodeAsync(user.Id);
                        return "2FA_REQUIRED";
                    }

                    var twoFactorModel = new TwoFactorModel { UserId = user.Id, Code = model.TwoFactorCode };
                    if (!await Verify2FACodeAsync(twoFactorModel))
                    {
                        return "Invalid 2FA code";
                    }
                }

                var token = await GenerateTokenAsync(user);
                if (string.IsNullOrEmpty(token))
                {
                    _logger.LogError("Failed to generate token for user: {Email}", model.Email);
                    return "Failed to generate authentication token";
                }

                await _unitOfWork.SaveChangesAsync();

                _logger.LogInformation("Login successful for user: {Email}", model.Email);
                return token;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login for user: {Email}", model.Email);
                return "An error occurred during login";
            }
        }

        public async Task<bool> Is2FAEnabledAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            return user != null && await _userManager.GetTwoFactorEnabledAsync(user);
        }

        public async Task<string> Disable2FAAsync(string userId)
        {
            try
            {
                var user = await _unitOfWork.UserRepository.FindByIdAsync(userId);
                if (user == null) return "User not found";

                await _userManager.SetTwoFactorEnabledAsync(user, false);

                user.OtpCode = null;
                user.OtpExpiry = null;
                _otpHelper.ResetFailedAttempts(user);

                var result = await _userManager.UpdateAsync(user);
                if (result.Succeeded)
                {
                    await _unitOfWork.SaveChangesAsync();
                    _logger.LogInformation("2FA disabled for user: {UserId}", userId);
                    return "2FA has been disabled successfully.";
                }

                return "Failed to disable 2FA.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error disabling 2FA for user: {UserId}", userId);
                return "An error occurred while disabling 2FA.";
            }
        }

        public async Task<string> ResendVerificationAsync(ResendVerificationModel model)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    _logger.LogWarning("Resend verification attempt with non-existent email: {Email}", model.Email);
                    return "User not found";
                }

                if (await _userManager.IsEmailConfirmedAsync(user))
                {
                    _logger.LogWarning("Email already confirmed for user: {Email}", model.Email);
                    return "Email is already confirmed";
                }

                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink =
                    $"http://localhost:3000/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";
                await _emailService.SendEmailAsync(user.Email, "Confirm your email",
                    $"Click <a href='{confirmationLink}'>here</a> to confirm your email.");
                await _unitOfWork.SaveChangesAsync();

                _logger.LogInformation("Verification email resent to: {Email}", model.Email);
                return "Verification email sent to your email.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resending verification email for: {Email}", model.Email);
                return "Failed to resend verification email.";
            }
        }

        public async Task<string> UpdateProfileAsync(string userId, UpdateProfileModel model)
        {
            var user = await _unitOfWork.UserRepository.FindByIdAsync(userId);
            if (user == null) return "User not found";

            user.PhoneNumber = model.PhoneNumber;
            user.AvatarUrl = model.AvatarUrl;

            if (!string.IsNullOrEmpty(user.PhoneNumber) &&
                !new System.ComponentModel.DataAnnotations.PhoneAttribute().IsValid(user.PhoneNumber))
                return "Invalid phone number format";

            if (!string.IsNullOrEmpty(user.AvatarUrl) &&
                !new System.ComponentModel.DataAnnotations.UrlAttribute().IsValid(user.AvatarUrl))
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
            try
            {
                var user = await _unitOfWork.UserRepository.FindByIdAsync(userId);
                if (user == null)
                {
                    _logger.LogWarning("User not found for 2FA generation: {UserId}", userId);
                    return "User not found";
                }

                if (_otpHelper.IsUserLockedOut(user))
                {
                    var remainingTime = user.OtpLockoutTime.Value.Subtract(DateTime.UtcNow);
                    _logger.LogWarning("User locked out for 2FA: {UserId}", userId);
                    return $"Too many failed attempts. Try again in {remainingTime.Minutes} minutes.";
                }

                if (user.OtpExpiry.HasValue &&
                    DateTime.UtcNow < user.OtpExpiry.Value.AddSeconds(-270))
                {
                    _logger.LogWarning("OTP request too frequent for user: {UserId}", userId);
                    return "Please wait 30 seconds before requesting a new OTP.";
                }

                var otpCode = _otpHelper.GenerateOtpCode();
                var hashedOtp = _otpHelper.HashOtpCode(otpCode);

                user.OtpCode = hashedOtp;
                user.OtpExpiry = _otpHelper.GetOtpExpiry();

                await _userManager.SetTwoFactorEnabledAsync(user, true);
                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    var emailBody = $@"
                        <h2>Your 2FA Verification Code</h2>
                        <p>Your verification code is: <strong>{otpCode}</strong></p>
                        <p>This code will expire in 5 minutes.</p>
                        <p>If you didn't request this code, please ignore this email.</p>
                    ";

                    await _emailService.SendEmailAsync(user.Email, "Your 2FA Verification Code", emailBody);
                    await _unitOfWork.SaveChangesAsync();

                    _logger.LogInformation("2FA code generated and sent for user: {UserId}", userId);
                    return "2FA code sent to your email.";
                }

                _logger.LogError("Failed to update user with 2FA code: {UserId}", userId);
                return "Failed to generate 2FA code.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating 2FA code for user: {UserId}", userId);
                return "An error occurred while generating 2FA code.";
            }
        }

        public async Task<bool> Verify2FACodeAsync(TwoFactorModel model)
        {
            try
            {
                if (!Regex.IsMatch(model.Code, @"^\d{6}$"))
                {
                    _logger.LogWarning("Invalid OTP code format for user: {UserId}", model.UserId);
                    return false;
                }

                var user = await _userManager.FindByIdAsync(model.UserId);
                if (user == null)
                {
                    _logger.LogWarning("User not found for 2FA verification: {UserId}", model.UserId);
                    return false;
                }

                if (_otpHelper.IsUserLockedOut(user))
                {
                    _logger.LogWarning("User locked out during 2FA verification: {UserId}", model.UserId);
                    return false;
                }

                if (string.IsNullOrEmpty(user.OtpCode) || _otpHelper.IsOtpExpired(user.OtpExpiry))
                {
                    _logger.LogWarning("OTP expired or not found for user: {UserId}", model.UserId);
                    return false;
                }

                bool isValidOtp = _otpHelper.VerifyOtpCode(model.Code, user.OtpCode);

                if (isValidOtp)
                {
                    user.OtpCode = null;
                    user.OtpExpiry = null;
                    _otpHelper.ResetFailedAttempts(user);

                    await _userManager.UpdateAsync(user);
                    await _unitOfWork.SaveChangesAsync();

                    _logger.LogInformation("2FA verification successful for user: {UserId}", model.UserId);
                    return true;
                }
                else
                {
                    _otpHelper.IncrementFailedAttempts(user);
                    await _userManager.UpdateAsync(user);
                    await _unitOfWork.SaveChangesAsync();

                    _logger.LogWarning("Invalid 2FA code for user: {UserId}. Attempts: {Attempts}",
                        model.UserId, user.OtpAttempts);
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying 2FA code for user: {UserId}", model.UserId);
                return false;
            }
        }

        public async Task<string> ForgotPasswordAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return "User not found";

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink =
                $"http://localhost:3000/reset-password?email={user.Email}&token={Uri.EscapeDataString(token)}";
            await _emailService.SendEmailAsync(user.Email, "Reset your password",
                $"Click <a href='{resetLink}'>here</a> to reset your password.");
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

            if (!await _userManager.CheckPasswordAsync(user, model.CurrentPassword))
                return "Current password is incorrect";

            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);

            if (result.Succeeded)
            {
                await _unitOfWork.SaveChangesAsync();
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