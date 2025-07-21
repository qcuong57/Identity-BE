using IdentityServer_BE.Models;
using IdentityServer_BE.Models.DTOs;
using IdentityServer_BE.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer_BE.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Admin")]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("create")]
        [AllowAnonymous]
        public async Task<IActionResult> CreateUser([FromBody] UserDto model)
        {
            try
            {
                if (!string.IsNullOrEmpty(model.AvatarUrl) &&
                    !Uri.IsWellFormedUriString(model.AvatarUrl, UriKind.Absolute))
                {
                    return BadRequest(new { Message = "Invalid avatar URL format" });
                }

                if (string.IsNullOrEmpty(model.Email) ||
                    !new System.ComponentModel.DataAnnotations.EmailAddressAttribute().IsValid(model.Email))
                {
                    return BadRequest(new { Message = "Email is invalid." });
                }

                var userId = await _userService.CreateUserAsync(model);
                if (!string.IsNullOrEmpty(userId) && !userId.Contains("Invalid") &&
                    !userId.Contains("is already in use"))
                    return Ok(new { UserId = userId, Message = "User created successfully" });
                return BadRequest(new { Message = userId });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = $"Lỗi khi tạo tài khoản: {ex.Message}" });
            }
        }

        [HttpPut("{userId}")]
        [AllowAnonymous]
        public async Task<IActionResult> UpdateUser(string userId, [FromBody] UpdateUserDto model)
        {
            try
            {
                // Validate avatar URL if provided
                if (!string.IsNullOrEmpty(model.AvatarUrl) &&
                    !Uri.IsWellFormedUriString(model.AvatarUrl, UriKind.Absolute))
                {
                    return BadRequest(new { Message = "Invalid avatar URL format" });
                }

                if (string.IsNullOrEmpty(model.Email) ||
                    !new System.ComponentModel.DataAnnotations.EmailAddressAttribute().IsValid(model.Email))
                {
                    return BadRequest(new { Message = "Email is invalid." });
                }

                // Convert UpdateUserDto to UserDto
                var userDto = new UserDto
                {
                    Id = userId,
                    Email = model.Email,
                    PhoneNumber = model.PhoneNumber,
                    Address = model.Address,
                    AvatarUrl = model.AvatarUrl,
                    Role = "User",
                    Status = "Active"
                };

                await _userService.UpdateUserAsync(userId, userDto);
                return Ok(new { Message = "User updated successfully" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = $"Lỗi khi cập nhật tài khoản: {ex.Message}" });
            }
        }

        [HttpPut("{userId}/lock")]
        public async Task<IActionResult> LockUser(string userId)
        {
            try
            {
                await _userService.LockUserAsync(userId);
                return Ok(new { Message = "User locked successfully" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPut("{userId}/unlock")]
        public async Task<IActionResult> UnlockUser(string userId)
        {
            try
            {
                await _userService.UnlockUserAsync(userId);
                return Ok(new { Message = "User unlocked successfully" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpDelete("{userId}")]
        public async Task<IActionResult> DeleteUser(string userId)
        {
            try
            {
                await _userService.DeleteUserAsync(userId);
                return Ok(new { Message = "User deleted successfully" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpGet("{userId}")]
        [AllowAnonymous]
        public async Task<IActionResult> GetUser(string userId)
        {
            try
            {
                var user = await _userService.GetUserByIdAsync(userId);
                return Ok(user);
            }
            catch (InvalidOperationException ex)
            {
                return NotFound(new { Message = ex.Message });
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> GetAllUsers(
            int pageNumber = 1,
            int pageSize = 10,
            string search = "",
            string status = "")
        {
            try
            {
                var users = await _userService.GetAllUsersAsync(pageNumber, pageSize, search, status);
                return Ok(users);
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPut("{userId}/change-password")]
        public async Task<IActionResult> ChangePassword(string userId, [FromBody] ChangePasswordDto model)
        {
            try
            {
                await _userService.ChangePasswordAsync(userId, model.CurrentPassword, model.NewPassword);
                return Ok(new { Message = "Password changed successfully" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPut("{userId}/reset-password")]
        public async Task<IActionResult> ResetPassword(string userId, [FromBody] ResetPasswordDto model)
        {
            try
            {
                await _userService.ResetPasswordAsync(userId, model.NewPassword);
                return Ok(new { Message = "Password reset successfully" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }
    }

    public class ChangePasswordDto
    {
        public string CurrentPassword { get; set; }
        public string NewPassword { get; set; }
    }

    public class ResetPasswordDto
    {
        public string NewPassword { get; set; }
    }
}