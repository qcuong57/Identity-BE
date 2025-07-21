using IdentityServer_BE.Models;
using IdentityServer_BE.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace IdentityServer_BE.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            IAuthService authService,
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            ILogger<AuthController> logger)
        {
            _authService = authService;
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var result = await _authService.RegisterAsync(model);
            if (result.Contains("successful"))
                return Ok(new { Message = result });
            return BadRequest(new { Message = result });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var result = await _authService.LoginAsync(model);

            if (result == "2FA_REQUIRED")
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                return Ok(new
                {
                    Message = "2FA required",
                    UserId = user.Id,
                    Requires2FA = true
                });
            }

            if (!result.Contains("Invalid") && !result.Contains("required") && !result.Contains("not confirmed"))
                return Ok(new { Token = result });

            if (result.Contains("not confirmed"))
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    var resendResult = await _authService.ResendVerificationAsync(new ResendVerificationModel { Email = model.Email });
                    return BadRequest(new { Message = result, EmailResent = resendResult.Contains("sent"), Detail = resendResult });
                }
                return BadRequest(new { Message = result });
            }

            return BadRequest(new { Message = result });
        }

        [HttpPost("resend-verification")]
        public async Task<IActionResult> ResendVerification([FromBody] ResendVerificationModel model)
        {
            try
            {
                var result = await _authService.ResendVerificationAsync(model);
                if (result.Contains("sent"))
                    return Ok(new { Message = result });
                return BadRequest(new { Message = result });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resending verification email for email: {Email}", model.Email);
                return BadRequest(new { Message = "Failed to resend verification email" });
            }
        }

        [HttpPost("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return BadRequest("Invalid user");
            var result = await _userManager.ConfirmEmailAsync(user, token);
            return result.Succeeded ? Ok("Email confirmed") : BadRequest("Invalid token");
        }

        [HttpPost("enable-2fa")]
        [Authorize]
        public async Task<IActionResult> Enable2FA()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                    return BadRequest(new { Message = "User not found" });

                await _userManager.SetTwoFactorEnabledAsync(user, true);

                return Ok(new { Message = "2FA enabled successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enabling 2FA for user {UserId}", userId);
                return BadRequest(new { Message = "Failed to enable 2FA" });
            }
        }

        [HttpPost("enable-2fa-with-verification")]
        [Authorize]
        public async Task<IActionResult> Enable2FAWithVerification()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var result = await _authService.Generate2FACodeAsync(userId);

            if (result.Contains("sent"))
                return Ok(new { Message = result });

            return BadRequest(new { Message = result });
        }

        [HttpPost("verify-2fa")]
        public async Task<IActionResult> Verify2FA([FromBody] TwoFactorModel model)
        {
            if (string.IsNullOrEmpty(model.UserId) || string.IsNullOrEmpty(model.Code))
                return BadRequest(new { Message = "UserId and Code are required" });

            var result = await _authService.Verify2FACodeAsync(model);

            if (result)
            {
                var user = await _userManager.FindByIdAsync(model.UserId);
                if (user == null)
                    return BadRequest(new { Message = "User not found" });

                if (!await _userManager.GetTwoFactorEnabledAsync(user))
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }

                var token = await _authService.GenerateTokenAsync(user);

                if (!string.IsNullOrEmpty(token))
                {
                    return Ok(new
                    {
                        Token = token,
                        Message = "2FA verified successfully"
                    });
                }
                else
                {
                    return Ok(new { Message = "2FA verified and enabled successfully" });
                }
            }

            return BadRequest(new { Message = "Invalid or expired 2FA code" });
        }

        [HttpPost("disable-2fa")]
        [Authorize]
        public async Task<IActionResult> Disable2FA()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                    return BadRequest(new { Message = "User not found" });

                await _userManager.SetTwoFactorEnabledAsync(user, false);

                return Ok(new { Message = "2FA disabled successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error disabling 2FA for user {UserId}", userId);
                return BadRequest(new { Message = "Failed to disable 2FA" });
            }
        }

        [HttpGet("2fa-status")]
        [Authorize]
        public async Task<IActionResult> Get2FAStatus()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                    return BadRequest(new { Message = "User not found" });

                var is2FAEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
                return Ok(new { Is2FAEnabled = is2FAEnabled });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting 2FA status for user {UserId}", userId);
                return BadRequest(new { Message = "Failed to get 2FA status" });
            }
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordModel model)
        {
            var result = await _authService.ForgotPasswordAsync(model.Email);
            return Ok(new { Message = result });
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel model)
        {
            var result = await _authService.ResetPasswordAsync(model);
            if (result.Contains("successful"))
                return Ok(new { Message = result });
            return BadRequest(new { Message = result });
        }

        [HttpPost("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordModel model)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var result = await _authService.ChangePasswordAsync(userId, model);

            if (result.Contains("successfully"))
                return Ok(new { Message = result });

            return BadRequest(new { Message = result });
        }

        [HttpPut("update-profile")]
        [Authorize]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileModel model)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId)) return Unauthorized();
            var result = await _authService.UpdateProfileAsync(userId, model);
            if (result.Contains("successfully"))
                return Ok(new { Message = result });
            return BadRequest(new { Message = result });
        }

        [HttpPost("login-with-2fa")]
        public async Task<IActionResult> LoginWith2FA([FromBody] LoginWith2FAModel model)
        {
            try
            {
                if (string.IsNullOrEmpty(model.Email) || string.IsNullOrEmpty(model.Code))
                {
                    return BadRequest(new { Message = "Email and Code are required" });
                }

                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return BadRequest(new { Message = "User not found" });
                }

                var verifyResult = await _authService.Verify2FACodeAsync(new TwoFactorModel
                {
                    UserId = user.Id,
                    Code = model.Code
                });

                if (!verifyResult)
                {
                    return BadRequest(new { Message = "Invalid or expired 2FA code" });
                }

                var token = await _authService.GenerateTokenAsync(user);

                if (!string.IsNullOrEmpty(token))
                {
                    return Ok(new
                    {
                        Token = token,
                        Message = "Login successful with 2FA"
                    });
                }
                else
                {
                    return BadRequest(new { Message = "Failed to generate token after 2FA verification" });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in LoginWith2FA");
                return BadRequest(new { Message = "Login with 2FA failed" });
            }
        }

        [HttpPost("resend-login-2fa")]
        public async Task<IActionResult> ResendLogin2FA([FromBody] ResendLogin2FAModel model)
        {
            try
            {
                string userId;

                if (!string.IsNullOrEmpty(model.UserId))
                {
                    userId = model.UserId;
                }
                else if (!string.IsNullOrEmpty(model.Email))
                {
                    var user = await _userManager.FindByEmailAsync(model.Email);
                    userId = user?.Id;
                }
                else
                {
                    return BadRequest(new { Message = "UserId or Email is required" });
                }

                if (string.IsNullOrEmpty(userId))
                {
                    return BadRequest(new { Message = "User not found" });
                }

                var result = await _authService.Generate2FACodeAsync(userId);

                if (result.Contains("sent"))
                    return Ok(new { Message = result });

                return BadRequest(new { Message = result });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ResendLogin2FA");
                return BadRequest(new { Message = "Failed to resend 2FA code" });
            }
        }
        [HttpPost("google-login")]
        public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginModel model)
        {
            try
            {
                // Verify Google ID token
                var payload = await Google.Apis.Auth.GoogleJsonWebSignature.ValidateAsync(model.IdToken);
        
                // Extract email and avatar URL
                var email = payload.Email;
                var avatarUrl = payload.Picture;

                // Check if user exists
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    // Create new user
                    user = new User
                    {
                        UserName = email,
                        Email = email,
                        AvatarUrl = avatarUrl, // Store avatar URL
                        EmailConfirmed = true // Google accounts are typically verified
                    };

                    var result = await _userManager.CreateAsync(user);
                    if (!result.Succeeded)
                    {
                        return BadRequest(new { Message = "Failed to create user: " + string.Join(", ", result.Errors.Select(e => e.Description)) });
                    }
                }
                else
                {
                    // Update existing user's avatar URL if needed
                    if (user.AvatarUrl != avatarUrl)
                    {
                        user.AvatarUrl = avatarUrl;
                        await _userManager.UpdateAsync(user);
                    }
                }

                // Generate JWT token
                var token = await _authService.GenerateTokenAsync(user);
                if (!string.IsNullOrEmpty(token))
                {
                    return Ok(new
                    {
                        Token = token,
                        Message = "Google login successful"
                    });
                }

                return BadRequest(new { Message = "Failed to generate token" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in Google login for email: {Email}", model.IdToken);
                return BadRequest(new { Message = "Google login failed: " + ex.Message });
            }
        }
    }
}