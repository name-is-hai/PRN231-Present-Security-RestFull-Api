
using Microsoft.AspNetCore.Identity;

namespace Api.Data
{
    public class ApplicationUser:IdentityUser
    {
        public string? Name { get; set; }
    }
}
