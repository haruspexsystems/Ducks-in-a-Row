namespace Certus.Adcs.ComInterop;

/// <summary>
/// Disposition values returned by ICertRequest::Submit and ICertRequest2::GetIssuedCertificate.
/// </summary>
internal static class DispositionCode
{
    public const int Incomplete = 0;
    public const int Error = 0x1;
    public const int Denied = 0x2;
    public const int Issued = 0x3;
    public const int IssuedOutOfBand = 0x4;
    public const int UnderSubmission = 0x5;
    public const int Revoked = 0x6;
}

/// <summary>
/// Input encoding and format flags for ICertRequest::Submit.
/// </summary>
internal static class RequestEncoding
{
    // Encoding
    public const int Base64Header = 0x0;
    public const int Base64 = 0x1;
    public const int Binary = 0x2;
    public const int EncodeAny = 0xff;
    public const int EncodeMask = 0xff;

    // Format
    public const int FormatAny = 0x0;
    public const int Pkcs10 = 0x100;
    public const int Keygen = 0x200;
    public const int Pkcs7 = 0x300;
    public const int Cmc = 0x400;
    public const int FormatMask = 0xff00;

    // Options
    public const int Rpc = 0x20000;
    public const int FullResponse = 0x40000;
    public const int ClientIdNone = 0x400000;
}

/// <summary>
/// Output encoding flags for ICertRequest::GetCertificate and ICertView column values.
/// </summary>
internal static class OutputEncoding
{
    public const int Base64Header = 0x0;
    public const int Base64 = 0x1;
    public const int Binary = 0x2;
    public const int EncodeMask = 0xff;
    public const int Chain = 0x100;
    public const int Crls = 0x200;
}

/// <summary>
/// CA property IDs for ICertRequest2::GetCAProperty and ICertAdmin2::GetCAProperty.
/// </summary>
internal static class CaPropertyId
{
    public const int FileVersion = 1;
    public const int ProductVersion = 2;
    public const int CaName = 6;
    public const int SanitizedCaName = 7;
    public const int CaType = 10;
    public const int CaSigCertCount = 11;
    public const int CaSigCert = 12;
    public const int CaSigCertChain = 13;
    public const int DnsName = 22;
    public const int Templates = 29;
    public const int SanitizedCaShortName = 40;
}

/// <summary>
/// Property type constants for GetCAProperty.
/// </summary>
internal static class PropertyType
{
    public const int Long = 0x1;
    public const int Date = 0x2;
    public const int Binary = 0x3;
    public const int String = 0x4;
}

/// <summary>
/// Database disposition values (different from request disposition).
/// </summary>
internal static class DbDisposition
{
    public const int Active = 8;
    public const int Pending = 9;
    public const int Issued = 20;
    public const int Revoked = 21;
    public const int Error = 30;
    public const int Denied = 31;
}

/// <summary>
/// ICertView seek operators for SetRestriction.
/// </summary>
internal static class SeekOperator
{
    public const int None = 0x0;
    public const int Equal = 0x1;
    public const int LessThan = 0x2;
    public const int LessOrEqual = 0x4;
    public const int GreaterOrEqual = 0x8;
    public const int GreaterThan = 0x10;
}

/// <summary>
/// ICertView sort order for SetRestriction.
/// </summary>
internal static class SortOrder
{
    public const int None = 0x0;
    public const int Ascend = 0x1;
    public const int Descend = 0x2;
}

/// <summary>
/// ICertView column schema vs result flags.
/// </summary>
internal static class ColumnType
{
    public const int Schema = 0x0;
    public const int Result = 0x1;
}

/// <summary>
/// Well-known CA database column names.
/// </summary>
internal static class ColumnName
{
    public const string RequestId = "RequestID";
    public const string Disposition = "Disposition";
    public const string DispositionMessage = "DispositionMessage";
    public const string StatusCode = "StatusCode";
    public const string SubmittedWhen = "SubmittedWhen";
    public const string ResolvedWhen = "ResolvedWhen";
    public const string RevokedWhen = "RevokedWhen";
    public const string RevokedReason = "RevokedReason";
    public const string RequesterName = "RequesterName";
    public const string CallerName = "CallerName";
    public const string SerialNumber = "SerialNumber";
    public const string NotBefore = "NotBefore";
    public const string NotAfter = "NotAfter";
    public const string RawCertificate = "RawCertificate";
    public const string CertificateHash = "CertificateHash";
    public const string CertificateTemplate = "CertificateTemplate";
    public const string CommonName = "CommonName";
    public const string DistinguishedName = "DistinguishedName";
    public const string SubjectKeyIdentifier = "SubjectKeyIdentifier";
    public const string PublicKeyLength = "PublicKeyLength";
}

/// <summary>
/// Request table columns whose unqualified name collides with a certificate
/// table column of the same name. The CA schema carries the subject twice: the
/// bare names are the issued certificate's ("Issued Common Name", "Issued
/// Distinguished Name") and the qualified ones are what the CSR asked for.
///
/// These live in their own type, and hold the qualified string, because here the
/// qualifier IS the identity. GetColumnIndex accepts either form when the query
/// is built, but IEnumCERTVIEWCOLUMN::GetName returns the canonical name on read
/// back, and the probe confirmed on the lab CA (2026-08-03) that it hands back
/// "Request.CommonName" qualified while the issued column comes back bare
/// "CommonName". Folding these into <see cref="ColumnName"/> would make the
/// constant "CommonName" mean two different columns depending on which one the
/// caller had in mind, which is the confusion this whole class of bug is made
/// of. <see cref="AdcsClient.NormalizeColumnName"/> keeps these two qualified so
/// the two values land under distinct keys.
/// </summary>
internal static class RequestColumnName
{
    public const string CommonName = "Request.CommonName";
    public const string DistinguishedName = "Request.DistinguishedName";
}
