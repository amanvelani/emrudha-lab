using System.Net;
using System.Net.Security;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Keys;

const string host = "labkeyvault1022.vault.azure.net";
const string keyName = "labkey";
const string keyVersion = "3858b94e860441a495683a7738aef277";
var logDir = Environment.GetEnvironmentVariable("LOG_DIR") ?? "/logs/client";
Directory.CreateDirectory(logDir);
var tokenPath = Environment.GetEnvironmentVariable("TOKEN_FILE") ?? "/run/secrets/token.json";
var runOnce = Environment.GetEnvironmentVariable("RUN_ONCE") != "false";
var probeOnly = Environment.GetEnvironmentVariable("TLS_PROBE_ONLY") == "true";
var credential = new FileTokenCredential(tokenPath);

void Log(object entry)
{
    var line = credential.Redact(JsonSerializer.Serialize(entry));
    File.AppendAllText(Path.Combine(logDir, "events.jsonl"), line + "\n");
    Console.WriteLine(line);
}

using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false };
handler.ServerCertificateCustomValidationCallback = (request, cert, chain, errors) =>
{
    Log(new {
        time = DateTimeOffset.UtcNow, type = "tls_validation",
        hostname = request.RequestUri?.Host, subject = cert?.Subject, issuer = cert?.Issuer,
        policyErrors = errors.ToString(),
        chain = chain?.ChainElements.Cast<System.Security.Cryptography.X509Certificates.X509ChainElement>()
            .Select(e => new { subject = e.Certificate.Subject, issuer = e.Certificate.Issuer,
                statuses = e.ChainElementStatus.Select(s => s.Status.ToString()).ToArray() }).ToArray()
    });
    // Log the platform's decision, and enforce it. No custom roots or bypasses.
    return errors == SslPolicyErrors.None;
};
using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(45) };
var options = new KeyClientOptions(KeyClientOptions.ServiceVersion.V7_4) {
    Transport = new HttpClientTransport(http)
};
options.Retry.MaxRetries = 0;
options.Retry.NetworkTimeout = TimeSpan.FromSeconds(30);
options.Diagnostics.IsLoggingEnabled = false;
options.Diagnostics.IsTelemetryEnabled = false;
var client = new KeyClient(new Uri($"https://{host}"), credential, options);
var hadFailure = false;

do
{
    try
    {
        Log(new { time = DateTimeOffset.UtcNow, type = "routing",
            host, addresses = (await Dns.GetHostAddressesAsync(host)).Select(a => a.ToString()).ToArray(),
            mode = probeOnly ? "unauthenticated_tls_probe" : "Azure.Security.KeyVault.Keys 4.10.2" });
        if (probeOnly)
        {
            using var response = await http.GetAsync($"https://{host}/keys/{keyName}/{keyVersion}?api-version=7.4");
            Log(new { time = DateTimeOffset.UtcNow, type = "probe_response", status = (int)response.StatusCode });
        }
        else
        {
            Response<KeyVaultKey> result = await client.GetKeyAsync(keyName, keyVersion);
            var raw = result.GetRawResponse();
            var body = credential.Redact(raw.Content.ToString());
            File.WriteAllText(Path.Combine(logDir, "response.json"), body);
            Log(new { time = DateTimeOffset.UtcNow, type = "sdk_response", status = raw.Status,
                keyId = result.Value.Id.ToString(), bodyFile = "response.json" });
        }
    }
    catch (Exception ex)
    {
        hadFailure = true;
        Log(new { time = DateTimeOffset.UtcNow, type = "error", exception = ex.GetType().Name,
            status = ex is RequestFailedException failed ? failed.Status : (int?)null,
            error = credential.Redact(ex.ToString()) });
    }
    if (!runOnce) await Task.Delay(TimeSpan.FromSeconds(60));
} while (!runOnce);
return hadFailure ? 1 : 0;

sealed class FileTokenCredential(string file) : TokenCredential
{
    private string? currentToken;

    public string Redact(string text) => string.IsNullOrEmpty(currentToken)
        ? text : text.Replace(currentToken, "[REDACTED]", StringComparison.Ordinal);

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        if (requestContext.Scopes.Length != 1 || requestContext.Scopes[0] != "https://vault.azure.net/.default")
            throw new InvalidOperationException("Credential is restricted to the Azure Key Vault scope.");
        using var json = JsonDocument.Parse(File.ReadAllText(file));
        currentToken = json.RootElement.GetProperty("accessToken").GetString()
            ?? throw new InvalidOperationException("Token file has no accessToken.");
        var value = json.RootElement.GetProperty("expires_on");
        long epoch = value.ValueKind == JsonValueKind.String ? long.Parse(value.GetString()!) : value.GetInt64();
        var expires = DateTimeOffset.FromUnixTimeSeconds(epoch);
        if (expires <= DateTimeOffset.UtcNow.AddMinutes(1))
            throw new InvalidOperationException("Azure CLI token expired; run ./run.py to refresh it.");
        return new AccessToken(currentToken, expires);
    }

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        => ValueTask.FromResult(GetToken(requestContext, cancellationToken));
}
