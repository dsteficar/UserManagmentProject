using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Request.Account
{
    public class CreateAccountDTO : LoginDTO
    {
        [Required]
        public string Name { get; set; }

        [Required, Compare(nameof(Password))]
        public string ConfirmPassword { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;

    }
}
