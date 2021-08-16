using System.Collections.Generic;
using System.Threading.Tasks;
using DGCValidator.Services.CWT.Certificates;

namespace DGCValidator.Services
{
    public interface IRestService
    {
        Task<DSC_TL> RefreshTrustListAsync(string pUrl);
        Task<Dictionary<string, string>> RefreshValueSetAsync();

        Task<string> RefreshTrustListAsyncAT(string pUrl);
    }
}
