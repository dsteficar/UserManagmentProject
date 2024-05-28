using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Request.Account
{
    public class LoginDTO
    {
        [EmailAddress, Required]
        [RegularExpression("[^@ \\t\\r\\n]+@[^@ \\t\\r\\n]+\\.[^@ \\t\\r\\n)]+",
            ErrorMessage = "Invalid Email Address")]
        [Display(Name = " Email Address")]
        public string EmailAddress { get; set; } = string.Empty;

        [Required]
        [RegularExpression("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^\\da-zA-Z]).{8,15}$",
           ErrorMessage = "Password must be between 8 and 15 characters and contain at least one lowercase letter, one uppercase letter, one numeric digit, and one special character.")]
        public string Password { get; set; } = string.Empty;    
    }
}
