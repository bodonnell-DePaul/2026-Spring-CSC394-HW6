using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;

// =============================================================================
// INTENTIONALLY INSECURE AUTH APP - CSC 436 Homework 5
// =============================================================================
// WARNING: This application contains 5 INTENTIONAL security vulnerabilities.
// It is designed for educational purposes ONLY. DO NOT deploy this to production.
//
// Vulnerabilities:
//   #1 - JWT stored in localStorage with no expiration check (see frontend/src/App.jsx)
//   #2 - Missing PKCE in OAuth flow (see /login, /callback, and mock OAuth routes)
//   #3 - Unvalidated API endpoint (see GET /api/user/profile)
//   #4 - Hardcoded client secret in front-end code (see frontend/src/App.jsx)
//   #5 - Missing HTTPS redirect (see middleware section below)
// =============================================================================

var builder = WebApplication.CreateBuilder(args);

var port = builder.Configuration["PORT"] ?? "5000";
builder.WebHost.UseUrls($"http://localhost:{port}");

var frontendUrl = builder.Configuration["FRONTEND_URL"] ?? "http://localhost:5173";
var backendBaseUrl = builder.Configuration["BACKEND_PUBLIC_URL"] ?? $"http://localhost:{port}";
var jwtSecret = builder.Configuration["JWT_SECRET"] ?? "my-jwt-signing-secret-for-demo";
var clientId = builder.Configuration["OAUTH_CLIENT_ID"] ?? "course-insecure-app-demo";
var clientSecret = builder.Configuration["OAUTH_CLIENT_SECRET"] ?? "super-secret-client-secret-12345";
var redirectUri = builder.Configuration["OAUTH_REDIRECT_URI"] ?? $"{backendBaseUrl}/callback";
var authEndpoint = builder.Configuration["OAUTH_AUTH_URL"] ?? $"{backendBaseUrl}/mock-auth/authorize";
var tokenEndpoint = builder.Configuration["OAUTH_TOKEN_URL"] ?? $"{backendBaseUrl}/mock-auth/token";

builder.Services.AddCors(options =>
{
    options.AddPolicy("Frontend", policy =>
    {
        policy.WithOrigins(frontendUrl)
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

builder.Services.AddHttpClient();

var app = builder.Build();

// -----------------------------------------------------------------------------
// Middleware
// -----------------------------------------------------------------------------

// VULNERABILITY #5: Missing HTTPS redirect
// In a production application, you MUST redirect HTTP traffic to HTTPS and set
// HSTS. This app intentionally does NOT call UseHttpsRedirection() or UseHsts().
// An attacker on the same network can intercept tokens, cookies, and user data.

app.UseCors("Frontend");

var tokenHandler = new JwtSecurityTokenHandler();
var signingKey = CreateSigningKey(jwtSecret);
var users = new Dictionary<string, MockUser>
{
    ["user-1"] = new("user-1", "Alice Johnson", "alice@example.com", "student"),
    ["user-2"] = new("user-2", "Bob Smith", "bob@example.com", "admin"),
};
var authCodes = new Dictionary<string, AuthCode>();

// -----------------------------------------------------------------------------
// Mock OAuth Authorization Server
// -----------------------------------------------------------------------------
// These routes simulate an external OAuth provider. In a real app, these would
// be hosted by Google, Microsoft, or another provider, not by your app.

app.MapGet("/mock-auth/authorize", (
    string? client_id,
    string? redirect_uri,
    string? response_type,
    string? state,
    string? scope,
    string? code_challenge,
    string? code_challenge_method) =>
{
    // VULNERABILITY #2: code_challenge and code_challenge_method are accepted
    // by the route signature but intentionally ignored. A secure OAuth server
    // would require PKCE for public clients and store the code_challenge here.

    if (response_type != "code")
    {
        return Results.Json(new { error = "unsupported_response_type" }, statusCode: 400);
    }

    if (string.IsNullOrWhiteSpace(redirect_uri))
    {
        return Results.Json(new { error = "invalid_request", error_description = "Missing redirect_uri" }, statusCode: 400);
    }

    var userId = "user-1";
    var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

    authCodes[code] = new AuthCode(
        UserId: userId,
        ClientId: client_id ?? string.Empty,
        RedirectUri: redirect_uri,
        State: state,
        CodeChallenge: null,
        CreatedAt: DateTimeOffset.UtcNow,
        ExpiresAt: DateTimeOffset.UtcNow.AddMinutes(10));

    var redirect = QueryHelpers.AddQueryString(redirect_uri, new Dictionary<string, string?>
    {
        ["code"] = code,
        ["state"] = state,
    });

    return Results.Redirect(redirect);
});

app.MapPost("/mock-auth/token", (TokenRequest request) =>
{
    // VULNERABILITY #2: request.CodeVerifier is intentionally ignored.

    if (request.GrantType != "authorization_code")
    {
        return Results.Json(new { error = "unsupported_grant_type" }, statusCode: 400);
    }

    if (string.IsNullOrWhiteSpace(request.Code) || !authCodes.TryGetValue(request.Code, out var authCode))
    {
        return Results.Json(new { error = "invalid_grant", error_description = "Invalid authorization code" }, statusCode: 400);
    }

    authCodes.Remove(request.Code);

    if (DateTimeOffset.UtcNow > authCode.ExpiresAt)
    {
        return Results.Json(new { error = "invalid_grant", error_description = "Authorization code expired" }, statusCode: 400);
    }

    if (request.ClientId != clientId || request.ClientSecret != clientSecret)
    {
        return Results.Json(new { error = "invalid_client" }, statusCode: 401);
    }

    // VULNERABILITY #2 continued: A secure implementation would hash the
    // code_verifier with SHA-256 and compare it to authCode.CodeChallenge.
    // Without this, an intercepted authorization code can be exchanged.

    var user = users[authCode.UserId];

    var accessToken = CreateJwt(tokenHandler, signingKey, new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id),
        new Claim("name", user.Name),
        new Claim(JwtRegisteredClaimNames.Email, user.Email),
        new Claim("role", user.Role),
        new Claim("type", "access"),
    }, expires: DateTime.UtcNow.AddHours(1));

    var idToken = CreateJwt(tokenHandler, signingKey, new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id),
        new Claim("name", user.Name),
        new Claim(JwtRegisteredClaimNames.Email, user.Email),
        new Claim("type", "id"),
    }, expires: DateTime.UtcNow.AddHours(1), issuer: backendBaseUrl, audience: clientId);

    var refreshToken = CreateJwt(tokenHandler, signingKey, new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id),
        new Claim("type", "refresh"),
    }, expires: DateTime.UtcNow.AddDays(7));

    return Results.Json(new
    {
        access_token = accessToken,
        id_token = idToken,
        refresh_token = refreshToken,
        token_type = "Bearer",
        expires_in = 3600,
    });
});

// -----------------------------------------------------------------------------
// Application Routes
// -----------------------------------------------------------------------------

app.MapGet("/", () => Results.Json(new
{
    name = "CSC 436 Insecure Auth App API",
    warning = "This API intentionally contains authentication vulnerabilities for homework use.",
    frontend = frontendUrl,
}));

app.MapGet("/login", () =>
{
    var state = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    // VULNERABILITY #2: Login initiates OAuth WITHOUT PKCE.
    // A secure public client would generate a code_verifier, derive a
    // code_challenge, store the verifier safely, and send these parameters:
    //   code_challenge=BASE64URL(SHA256(code_verifier))
    //   code_challenge_method=S256
    var authUrl = QueryHelpers.AddQueryString(authEndpoint, new Dictionary<string, string?>
    {
        ["client_id"] = clientId,
        ["redirect_uri"] = redirectUri,
        ["response_type"] = "code",
        ["scope"] = "openid profile email",
        ["state"] = state,
    });

    return Results.Redirect(authUrl);
});

app.MapGet("/callback", async (string? code, string? state, IHttpClientFactory httpClientFactory) =>
{
    if (string.IsNullOrWhiteSpace(code))
    {
        return Results.Text("Missing authorization code", statusCode: 400);
    }

    try
    {
        var httpClient = httpClientFactory.CreateClient();
        var tokenResponse = await httpClient.PostAsJsonAsync(tokenEndpoint, new TokenRequest(
            GrantType: "authorization_code",
            Code: code,
            RedirectUri: redirectUri,
            ClientId: clientId,
            ClientSecret: clientSecret,
            CodeVerifier: null));

        var tokens = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();

        if (tokens is null || !string.IsNullOrWhiteSpace(tokens.Error))
        {
            return Results.Json(tokens ?? new TokenResponse(Error: "token_exchange_failed"), statusCode: 400);
        }

        // VULNERABILITY #1: Tokens are sent to the React app in the URL fragment,
        // where the front end stores them in localStorage.
        var dashboardUrl = new StringBuilder($"{frontendUrl}/dashboard");
        dashboardUrl.Append("#access_token=").Append(Uri.EscapeDataString(tokens.AccessToken ?? string.Empty));
        dashboardUrl.Append("&id_token=").Append(Uri.EscapeDataString(tokens.IdToken ?? string.Empty));
        dashboardUrl.Append("&refresh_token=").Append(Uri.EscapeDataString(tokens.RefreshToken ?? string.Empty));
        dashboardUrl.Append("&expires_in=").Append(tokens.ExpiresIn ?? 3600);

        return Results.Redirect(dashboardUrl.ToString());
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Token exchange failed");
        return Results.Text("Authentication failed", statusCode: 500);
    }
});

app.MapGet("/api/user/profile", (HttpRequest request) =>
{
    var bearerToken = GetBearerToken(request);

    if (string.IsNullOrWhiteSpace(bearerToken))
    {
        return Results.Json(new { error = "No token provided" }, statusCode: 401);
    }

    try
    {
        // VULNERABILITY #3: ReadJwtToken decodes the JWT but does NOT validate
        // the signature or expiration. Anyone can forge a token and this route
        // will trust its claims.
        var decoded = tokenHandler.ReadJwtToken(bearerToken);

        return Results.Json(new
        {
            id = GetClaim(decoded, JwtRegisteredClaimNames.Sub),
            name = GetClaim(decoded, "name"),
            email = GetClaim(decoded, JwtRegisteredClaimNames.Email),
            role = GetClaim(decoded, "role"),
            message = "Profile retrieved successfully",
        });
    }
    catch
    {
        return Results.Json(new { error = "Invalid token format" }, statusCode: 401);
    }
});

app.MapPost("/api/data", (HttpRequest request) =>
{
    var bearerToken = GetBearerToken(request);

    if (string.IsNullOrWhiteSpace(bearerToken))
    {
        return Results.Json(new { error = "No token provided" }, statusCode: 401);
    }

    try
    {
        var principal = tokenHandler.ValidateToken(bearerToken, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
        }, out _);

        return Results.Json(new
        {
            data = new[]
            {
                new { id = 1, title = "Project Alpha", status = "active" },
                new { id = 2, title = "Project Beta", status = "completed" },
                new { id = 3, title = "Project Gamma", status = "planning" },
            },
            user = principal.FindFirstValue("name"),
            message = "Protected data retrieved successfully",
        });
    }
    catch (SecurityTokenExpiredException)
    {
        return Results.Json(new { error = "Token expired" }, statusCode: 401);
    }
    catch
    {
        return Results.Json(new { error = "Invalid token" }, statusCode: 401);
    }
});

app.MapGet("/logout", () =>
{
    // In a properly secured app, logout would clear httpOnly cookies, revoke the
    // refresh token when supported, and clear server-side session state. Because
    // this vulnerable starter stores tokens in localStorage, logout is handled
    // in the React client.
    return Results.Redirect(frontendUrl);
});

app.Logger.LogWarning("INSECURE AUTH APP - For educational purposes only");
app.Logger.LogInformation("API running at {BackendUrl}", backendBaseUrl);
app.Logger.LogInformation("React front end expected at {FrontendUrl}", frontendUrl);
app.Logger.LogInformation("This app contains 5 intentional security vulnerabilities.");

app.Run();

static SymmetricSecurityKey CreateSigningKey(string secret)
{
    var keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
    return new SymmetricSecurityKey(keyBytes);
}

static string CreateJwt(
    JwtSecurityTokenHandler tokenHandler,
    SecurityKey signingKey,
    IEnumerable<Claim> claims,
    DateTime expires,
    string? issuer = null,
    string? audience = null)
{
    var descriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(claims),
        Expires = expires,
        IssuedAt = DateTime.UtcNow,
        Issuer = issuer,
        Audience = audience,
        SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256),
    };

    return tokenHandler.WriteToken(tokenHandler.CreateToken(descriptor));
}

static string? GetBearerToken(HttpRequest request)
{
    var authHeader = request.Headers.Authorization.ToString();
    if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
    {
        return null;
    }

    return authHeader["Bearer ".Length..].Trim();
}

static string? GetClaim(JwtSecurityToken token, string claimType)
{
    return token.Claims.FirstOrDefault(claim => claim.Type == claimType)?.Value;
}

public sealed record MockUser(string Id, string Name, string Email, string Role);

public sealed record AuthCode(
    string UserId,
    string ClientId,
    string RedirectUri,
    string? State,
    string? CodeChallenge,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt);

public sealed record TokenRequest(
    [property: JsonPropertyName("grant_type")] string? GrantType,
    [property: JsonPropertyName("code")] string? Code,
    [property: JsonPropertyName("redirect_uri")] string? RedirectUri,
    [property: JsonPropertyName("client_id")] string? ClientId,
    [property: JsonPropertyName("client_secret")] string? ClientSecret,
    [property: JsonPropertyName("code_verifier")] string? CodeVerifier);

public sealed record TokenResponse(
    [property: JsonPropertyName("access_token")] string? AccessToken = null,
    [property: JsonPropertyName("id_token")] string? IdToken = null,
    [property: JsonPropertyName("refresh_token")] string? RefreshToken = null,
    [property: JsonPropertyName("token_type")] string? TokenType = null,
    [property: JsonPropertyName("expires_in")] int? ExpiresIn = null,
    [property: JsonPropertyName("error")] string? Error = null,
    [property: JsonPropertyName("error_description")] string? ErrorDescription = null);
