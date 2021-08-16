using System;
namespace DGCValidator.Models
{
    public interface ICertModel
    {
        CertType Type { get; set; }
        string Header { get; set; }
        string Info { get; set; }
        void CreateHeaderAndInfo();

    }
}
