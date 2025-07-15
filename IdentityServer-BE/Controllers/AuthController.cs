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
            if (!result.Contains("Invalid") && !result.Contains("required") && !result.Contains("not confirmed"))
                return Ok(new { Token = result });
            return BadRequest(new { Message = result });
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
            if (string.IsNullOrEmpty(userId)) return Unauthorized();
            var result = await _authService.Generate2FACodeAsync(userId);
            return Ok(new { Message = "2FA code sent to email", Code = result });
        }

        [HttpPost("verify-2fa")]
        public async Task<IActionResult> Verify2FA([FromBody] TwoFactorModel model)
        {
            var result = await _authService.Verify2FACodeAsync(model);
            return result ? Ok("2FA verified") : BadRequest("Invalid 2FA code");
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

        // [HttpGet("google-login")]
        // [AllowAnonymous]
        // public IActionResult GoogleLogin(string returnUrl = null)
        // {
        //     try
        //     {
        //         var redirectUrl = Url.Action(nameof(GoogleCallback), "Auth", new { returnUrl }, Request.Scheme);
        //         var properties = _signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
        //         properties.Items["returnUrl"] = returnUrl ?? "http://localhost:3000";
        //
        //         _logger.LogInformation($"Initiating Google login with redirect URL: {redirectUrl}");
        //         return Challenge(properties, "Google");
        //     }
        //     catch (Exception ex)
        //     {
        //         _logger.LogError(ex, "Google login error");
        //         return BadRequest(new { Message = "Google login failed" });
        //     }
        // }
        //
        // [HttpGet("google-callback")]
        // [AllowAnonymous]
        // public async Task<IActionResult> GoogleCallback(string returnUrl = null, string remoteError = null)
        // {
        //     try
        //     {
        //         if (remoteError != null)
        //         {
        //             _logger.LogError($"Google authentication failed: {remoteError}");
        //             return Redirect($"{returnUrl ?? "http://localhost:3000"}/auth-callback?error={Uri.EscapeDataString(remoteError)}");
        //         }
        //
        //         var info = await _signInManager.GetExternalLoginInfoAsync();
        //         if (info == null)
        //         {
        //             _logger.LogError("Failed to retrieve Google login information");
        //             return Redirect($"{returnUrl ?? "http://localhost:3000"}/auth-callback?error=Failed to retrieve login information");
        //         }
        //
        //         var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
        //         User user;
        //
        //         if (result.Succeeded)
        //         {
        //             user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        //         }
        //         else
        //         {
        //             var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        //             if (string.IsNullOrEmpty(email))
        //             {
        //                 _logger.LogError("Google did not provide an email");
        //                 return Redirect($"{returnUrl ?? "http://localhost:3000"}/auth-callback?error=Email not provided");
        //             }
        //
        //             user = await _userManager.FindByEmailAsync(email);
        //             if (user == null)
        //             {
        //                 user = new User
        //                 {
        //                     UserName = email,
        //                     Email = email,
        //                     EmailConfirmed = true,
        //                     Status = "Active",
        //                     Role = "User"
        //                 };
        //                 var createResult = await _userManager.CreateAsync(user);
        //                 if (!createResult.Succeeded)
        //                 {
        //                     var errors = string.Join(", ", createResult.Errors.Select(e => e.Description));
        //                     _logger.LogError($"User creation failed: {errors}");
        //                     return Redirect($"{returnUrl ?? "http://localhost:3000"}/auth-callback?error=User creation failed: {Uri.EscapeDataString(errors)}");
        //                 }
        //             }
        //
        //             var addLoginResult = await _userManager.AddLoginAsync(user, info);
        //             if (!addLoginResult.Succeeded)
        //             {
        //                 var errors = string.Join(", ", addLoginResult.Errors.Select(e => e.Description));
        //                 _logger.LogError($"Adding Google login failed: {errors}");
        //                 return Redirect($"{returnUrl ?? "http://localhost:3000"}/auth-callback?error=Adding Google login failed: {Uri.EscapeDataString(errors)}");
        //             }
        //
        //             await _signInManager.SignInAsync(user, isPersistent: false);
        //         }
        //
        //         var token = await _authService.LoginAsync(new LoginModel { Email = user.Email, Password = null }, true);
        //         if (!token.Contains("Invalid") && !token.Contains("required") && !token.Contains("not confirmed"))
        //         {
        //             _logger.LogInformation("Google login successful, JWT token generated");
        //             return Redirect($"{returnUrl ?? "http://localhost:3000"}/auth-callback?token={Uri.EscapeDataString(token)}&email={Uri.EscapeDataString(user.Email)}");
        //         }
        //
        //         _logger.LogError($"JWT token generation failed: {token}");
        //         return Redirect($"{returnUrl ?? "http://localhost:3000"}/auth-callback?error=Login failed: {Uri.EscapeDataString(token)}");
        //     }
        //     catch (Exception ex)
        //     {
        //         _logger.LogError(ex, "Google callback error");
        //         return Redirect($"{returnUrl ?? "http://localhost:3000"}/auth-callback?error=Google login failed: {Uri.EscapeDataString(ex.Message)}");
        //     }
        // }
    }
}