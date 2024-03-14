using Microsoft.AspNetCore.Identity;
using RoleAuth.Models.Domain;
using RoleAuth.Models.DTO;
using RoleAuth.Repositories.Abstract;
using System.Security.Claims;

namespace RoleAuth.Repositories.Implementation
{
    public class UserAuthenticationService : IUserAuthenticationService
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public UserAuthenticationService(SignInManager<ApplicationUser> signInManager , UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
            _signInManager = signInManager;
            _userManager = userManager;
        }
        public async Task<Status> LoginAsync(LoginModel model)
        {
           var status = new Status();
            var user = await _userManager.FindByNameAsync(model.UserName);
            if(user == null)
            {
                status.StatusCode = 0;
                status.Message = "User Not Found";
                return status;
            }
            //checking the password
            if(!await _userManager.CheckPasswordAsync(user, model.Password)){
                status.StatusCode = 0;
                status.Message = "Incorrect Password";
                return status;
            }
            var signInResult = await _signInManager.PasswordSignInAsync(user, model.Password, true, false);
           
            if (signInResult.Succeeded)
            {
               var userRole = await _userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                  new Claim(ClaimTypes.Name, user.UserName)
                };
                foreach (var item in userRole)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, item));
                }
                status.StatusCode = 1;
                status.Message = "Login Success";
                return status;
                }

                else if (signInResult.IsLockedOut)
                {
                    status.StatusCode = 0;
                    status.Message = "Account Locked";
                    return status;
                }
                else
                {
                    status.StatusCode = 0;
                    status.Message = "Login Failed";
                    return status;
                }

            status.StatusCode = 1;
            status.Message = "Login Success";
            return status;
            }

        

     
        public async Task LogoutAsync()
        {
            await _signInManager.SignOutAsync();
        }

        public async Task<Status> RegisterAsync(RegistrationModel model)
        {
            var status = new Status();
            var userExist = await _userManager.FindByNameAsync(model.Username);
            if (userExist != null)
            {
                status.Message = "User Already Exist";
                status.StatusCode = 0;
                return status;
            }

            ApplicationUser user = new ApplicationUser
            {
                SecurityStamp = Guid.NewGuid().ToString(),
                Name = model.Name,
                UserName = model.Username,
                Email = model.Email,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                status.Message = "User Creation Failed";
                status.StatusCode = 0;
                return status;
            }

            // Role management
            if (!await _roleManager.RoleExistsAsync(model.Role))
            {
                var roleResult = await _roleManager.CreateAsync(new IdentityRole(model.Role));
                if (!roleResult.Succeeded)
                {
                    status.Message = "Role Creation Failed";
                    status.StatusCode = 0;
                    return status;
                }
            }

            if (await _roleManager.RoleExistsAsync(model.Role))
            {
                var addToRoleResult = await _userManager.AddToRoleAsync(user, model.Role);
                if (!addToRoleResult.Succeeded)
                {
                    status.Message = "Failed to assign role to user";
                    status.StatusCode = 0;
                    return status;
                }
            }

            status.StatusCode = 1;
            status.Message = "User Created Successfully";
            return status;
        }

    }
}
