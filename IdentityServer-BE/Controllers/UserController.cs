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
            var userId = await _userService.CreateUserAsync(model);
            if (!string.IsNullOrEmpty(userId) && !userId.Contains("Invalid"))
                return Ok(new { UserId = userId, Message = "User created successfully" });
            return BadRequest(new { Message = userId });
        }

        [HttpPut("{userId}")]
        [AllowAnonymous]
        public async Task<IActionResult> UpdateUser(string userId, [FromBody] UserDto model)
        {
            try
            {
                await _userService.UpdateUserAsync(userId, model);
                return Ok(new { Message = "User updated successfully" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPut("{userId}/lock")]
        [AllowAnonymous]
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
        [AllowAnonymous]
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
        [AllowAnonymous]
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
        public async Task<IActionResult> GetAllUsers(int pageNumber = 1, int pageSize = 10)
        {
            var users = await _userService.GetAllUsersAsync(pageNumber, pageSize);
            return Ok(users);
        }

        [HttpPut("{userId}/change-password")]
        [AllowAnonymous]
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
        [AllowAnonymous]
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

    // DTO classes for password operations
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