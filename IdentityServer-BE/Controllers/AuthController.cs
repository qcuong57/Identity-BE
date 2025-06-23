using IdentityServer_BE.Models;
using IdentityServer_BE.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace IdentityServer_BE.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;

        public AuthController(
            IAuthService authService,
            UserManager<User> userManager,
            SignInManager<User> signInManager)
        {
            _authService = authService;
            _userManager = userManager;
            _signInManager = signInManager;
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
        public async Task<IActionResult> ForgotPassword([FromBody] string email)
        {
            var result = await _authService.ForgotPasswordAsync(email);
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

        [HttpGet("google-login")]
        [AllowAnonymous]
        public IActionResult GoogleLogin(string returnUrl = null)
        {
            var redirectUrl = Url.Action(nameof(GoogleCallback), "Auth", new { returnUrl }, Request.Scheme);
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
            return Challenge(properties, "Google");
        }

        [HttpGet("google-callback")]
        [AllowAnonymous]
        public async Task<IActionResult> GoogleCallback(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
            {
                return BadRequest(new { Message = $"Error from Google: {remoteError}" });
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return BadRequest(new { Message = "Error loading external login information" });
            }

            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                user = new User
                {
                    UserName = email,
                    Email = email,
                    EmailConfirmed = true,
                    Status = "Active",
                    Role = "User"
                };

                var result = await _userManager.CreateAsync(user);
                if (!result.Succeeded)
                {
                    return BadRequest(new { Message = string.Join(", ", result.Errors.Select(e => e.Description)) });
                }

                result = await _userManager.AddLoginAsync(user, info);
                if (!result.Succeeded)
                {
                    return BadRequest(new { Message = string.Join(", ", result.Errors.Select(e => e.Description)) });
                }
            }

            var token = await _authService.LoginAsync(new LoginModel { Email = email, Password = null }, true);
            if (!token.Contains("Invalid") && !token.Contains("required") && !token.Contains("not confirmed"))
            {
                return Ok(new { Token = token });
            }

            return BadRequest(new { Message = token });
        }
    }
}