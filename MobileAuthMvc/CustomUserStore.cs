using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace MobileAuthMvc
{
    public sealed class CustomUserStore : IUserLoginStore<User>, IUserStore<User>
    {
        private HashSet<User> _users = new HashSet<User>();
        private HashSet<UserUserLoginsInfo> _userLoginsInfos = new HashSet<UserUserLoginsInfo>();

        public void Dispose()
        {
        }

        public async Task CreateAsync(User user)
        {
            var existUser = await FindByIdAsync(user.Id);
            if (existUser is null) _users.Add(user);
        }

        public async Task UpdateAsync(User user)
        {
            var existUser = await FindByIdAsync(user.Id);
            existUser.UserName = user.UserName;
        }

        public Task DeleteAsync(User user)
        {
            _users.Remove(user);
            return Task.CompletedTask;
        }

        public Task<User> FindByIdAsync(string userId)
        {
            return Task.FromResult(_users.FirstOrDefault(x => x.Id == userId));
        }

        public Task<User> FindByNameAsync(string userName)
        {
            return Task.FromResult(_users.FirstOrDefault(x => x.UserName == userName));
        }

        public Task AddLoginAsync(User user, UserLoginInfo login)
        {
            var existUserInfos = _userLoginsInfos.FirstOrDefault(x => x.User.Id == user.Id);
            if (existUserInfos == null) _userLoginsInfos.Add(new UserUserLoginsInfo(user, new List<UserLoginInfo> { login }));
            else if (existUserInfos.UserLoginInfos.FirstOrDefault(x => x.ProviderKey == login.ProviderKey) != null) return Task.CompletedTask;
            else existUserInfos.UserLoginInfos.Add(login);
            return Task.CompletedTask;
        }

        public Task RemoveLoginAsync(User user, UserLoginInfo login)
        {
            var existUserInfos = _userLoginsInfos.FirstOrDefault(x => x.User.Id == user.Id);
            var existLogin = existUserInfos?.UserLoginInfos.FirstOrDefault(x => x.ProviderKey == login.ProviderKey);
            if (existLogin != null) existUserInfos.UserLoginInfos.Remove(existLogin);
            return Task.CompletedTask;
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(User user)
        {
            var existUserInfos = _userLoginsInfos.FirstOrDefault(x => x.User.Id == user.Id);
            return Task.FromResult<IList<UserLoginInfo>>(existUserInfos != null
                ? existUserInfos.UserLoginInfos
                : Enumerable.Empty<UserLoginInfo>().ToList());
        }

        public Task<User> FindAsync(UserLoginInfo login)
        {
            return Task.FromResult<User>(null);
        }
    }

    public sealed class UserUserLoginsInfo
    {
        public User User { get; }
        public List<UserLoginInfo> UserLoginInfos { get; }

        public UserUserLoginsInfo(User user, List<UserLoginInfo> userLoginInfos)
        {
            User = user;
            UserLoginInfos = userLoginInfos;
        }
    }

    public sealed class User : IUser<string>
    {
        public string Id { get; }
        public string UserName { get; set; }
        public string PasswordHash { get; set; }

        public User(string id) => Id = id;
    }
}