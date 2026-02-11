<p align="center">
  <img src="./assets/logo.png" alt="SafeNest" width="200" />
</p>

<h1 align="center">SafeNest Unity SDK</h1>

<p align="center">
  <strong>Official Unity SDK for the SafeNest API</strong><br>
  AI-powered child safety analysis
</p>

<p align="center">
  <a href="https://github.com/SafeNestSDK/unity/actions"><img src="https://img.shields.io/github/actions/workflow/status/SafeNestSDK/unity/ci.yml" alt="build status"></a>
  <a href="https://github.com/SafeNestSDK/unity/blob/main/LICENSE.md"><img src="https://img.shields.io/github/license/SafeNestSDK/unity.svg" alt="license"></a>
</p>

<p align="center">
  <a href="https://api.safenest.dev/docs">API Docs</a> •
  <a href="https://safenest.app">Dashboard</a> •
  <a href="https://discord.gg/7kbTeRYRXD">Discord</a>
</p>

---

## Installation

### Unity Package Manager (Git URL)

1. Open Window → Package Manager
2. Click "+" → "Add package from git URL..."
3. Enter: `https://github.com/SafeNestSDK/unity.git`
4. Click "Add"

### Manual Installation

1. Download the latest release
2. Extract to your `Packages/` folder

### Requirements

- Unity 2021.3+
- .NET Standard 2.1

---

## Quick Start

```csharp
using SafeNest;
using UnityEngine;

public class Example : MonoBehaviour
{
    private SafeNestClient client;

    void Start()
    {
        client = new SafeNestClient("your-api-key");
        CheckMessage("Hello world");
    }

    async void CheckMessage(string message)
    {
        var result = await client.AnalyzeAsync(message);

        if (result.RiskLevel != RiskLevel.Safe)
        {
            Debug.Log($"Risk: {result.RiskLevel}");
            Debug.Log($"Summary: {result.Summary}");
        }
    }
}
```

---

## API Reference

### Initialization

```csharp
using SafeNest;

// Simple
var client = new SafeNestClient("your-api-key");

// With options
var client = new SafeNestClient(
    apiKey: "your-api-key",
    timeout: 30f,        // Request timeout in seconds
    maxRetries: 3,       // Retry attempts
    retryDelay: 1f       // Initial retry delay in seconds
);
```

### Bullying Detection

```csharp
var result = await client.DetectBullyingAsync("Nobody likes you, just leave");

if (result.IsBullying)
{
    Debug.Log($"Severity: {result.Severity}");        // Medium
    Debug.Log($"Types: {result.BullyingType}");       // [exclusion, verbal_abuse]
    Debug.Log($"Confidence: {result.Confidence}");   // 0.92
    Debug.Log($"Rationale: {result.Rationale}");
}
```

### Grooming Detection

```csharp
var result = await client.DetectGroomingAsync(new DetectGroomingInput
{
    Messages = new List<GroomingMessage>
    {
        new GroomingMessage(MessageRole.Adult, "This is our secret"),
        new GroomingMessage(MessageRole.Child, "Ok I wont tell")
    },
    ChildAge = 12
});

if (result.GroomingRisk == GroomingRisk.High)
{
    Debug.Log($"Flags: {string.Join(", ", result.Flags)}");
}
```

### Unsafe Content Detection

```csharp
var result = await client.DetectUnsafeAsync("I dont want to be here anymore");

if (result.Unsafe)
{
    Debug.Log($"Categories: {string.Join(", ", result.Categories)}");
    Debug.Log($"Severity: {result.Severity}");
}
```

### Quick Analysis

Runs bullying and unsafe detection:

```csharp
var result = await client.AnalyzeAsync("Message to check");

Debug.Log($"Risk Level: {result.RiskLevel}");   // Safe/Low/Medium/High/Critical
Debug.Log($"Risk Score: {result.RiskScore}");   // 0.0 - 1.0
Debug.Log($"Summary: {result.Summary}");
Debug.Log($"Action: {result.RecommendedAction}");
```

### Emotion Analysis

```csharp
var result = await client.AnalyzeEmotionsAsync("Im so stressed about everything");

Debug.Log($"Emotions: {string.Join(", ", result.DominantEmotions)}");
Debug.Log($"Trend: {result.Trend}");
Debug.Log($"Followup: {result.RecommendedFollowup}");
```

### Action Plan

```csharp
var plan = await client.GetActionPlanAsync(new GetActionPlanInput
{
    Situation = "Someone is spreading rumors about me",
    ChildAge = 12,
    Audience = Audience.Child,
    Severity = Severity.Medium
});

Debug.Log($"Steps: {string.Join("\n", plan.Steps)}");
Debug.Log($"Tone: {plan.Tone}");
```

### Incident Report

```csharp
var report = await client.GenerateReportAsync(new GenerateReportInput
{
    Messages = new List<ReportMessage>
    {
        new ReportMessage("user1", "Threatening message"),
        new ReportMessage("child", "Please stop")
    },
    ChildAge = 14
});

Debug.Log($"Summary: {report.Summary}");
Debug.Log($"Risk: {report.RiskLevel}");
```

---

## Tracking Fields

All methods support `externalId` and `metadata` for correlating requests:

```csharp
var result = await client.DetectBullyingAsync(
    content: "Test message",
    externalId: "msg_12345",
    metadata: new Dictionary<string, object>
    {
        { "user_id", "usr_abc" },
        { "session", "sess_xyz" }
    }
);

// Echoed back in response
Debug.Log(result.ExternalId);  // msg_12345
Debug.Log(result.Metadata);    // {user_id: usr_abc, ...}
```

---

## Usage Tracking

```csharp
var result = await client.DetectBullyingAsync("test");

// Access usage stats after any request
if (client.Usage != null)
{
    Debug.Log($"Limit: {client.Usage.Limit}");
    Debug.Log($"Used: {client.Usage.Used}");
    Debug.Log($"Remaining: {client.Usage.Remaining}");
}

// Request metadata
Debug.Log($"Request ID: {client.LastRequestId}");
```

---

## Error Handling

```csharp
using SafeNest;

try
{
    var result = await client.DetectBullyingAsync("test");
}
catch (AuthenticationException e)
{
    Debug.LogError($"Auth error: {e.Message}");
}
catch (RateLimitException e)
{
    Debug.LogError($"Rate limited: {e.Message}");
}
catch (ValidationException e)
{
    Debug.LogError($"Invalid input: {e.Message}, details: {e.Details}");
}
catch (ServerException e)
{
    Debug.LogError($"Server error {e.StatusCode}: {e.Message}");
}
catch (TimeoutException e)
{
    Debug.LogError($"Timeout: {e.Message}");
}
catch (NetworkException e)
{
    Debug.LogError($"Network error: {e.Message}");
}
catch (SafeNestException e)
{
    Debug.LogError($"Error: {e.Message}");
}
```

---

## Chat Filter Example

```csharp
using SafeNest;
using UnityEngine;
using UnityEngine.UI;

public class ChatFilter : MonoBehaviour
{
    [SerializeField] private InputField messageInput;
    [SerializeField] private Button sendButton;
    [SerializeField] private Text statusText;

    private SafeNestClient client;

    void Start()
    {
        client = new SafeNestClient("your-api-key");
        sendButton.onClick.AddListener(OnSendClicked);
    }

    async void OnSendClicked()
    {
        var message = messageInput.text;
        if (string.IsNullOrEmpty(message)) return;

        sendButton.interactable = false;
        statusText.text = "Checking...";

        try
        {
            var result = await client.AnalyzeAsync(message);

            if (result.RiskLevel == RiskLevel.Critical ||
                result.RiskLevel == RiskLevel.High)
            {
                statusText.text = $"Message blocked: {result.Summary}";
                return;
            }

            // Safe - send the message
            statusText.text = "Message sent!";
            messageInput.text = "";
            // SendToServer(message);
        }
        catch (SafeNestException e)
        {
            statusText.text = $"Error: {e.Message}";
        }
        finally
        {
            sendButton.interactable = true;
        }
    }
}
```

---

## Best Practices

### Message Batching

The **bullying** and **unsafe content** methods analyze a single `text` field per request. If your game receives messages one at a time (e.g., in-game chat), concatenate a **sliding window of recent messages** into one string before calling the API. Single words or short fragments lack context for accurate detection and can be exploited to bypass safety filters.

```csharp
// Bad — each message analyzed in isolation, easily evaded
foreach (var msg in messages)
{
    await client.DetectBullying(text: msg);
}

// Good — recent messages analyzed together
var window = string.Join(" ", recentMessages.TakeLast(10));
await client.DetectBullying(text: window);
```

The **grooming** method already accepts a `messages` array and analyzes the full conversation in context.

### PII Redaction

Enable `PII_REDACTION_ENABLED=true` on your SafeNest API to automatically strip emails, phone numbers, URLs, social handles, IPs, and other PII from detection summaries and webhook payloads. The original text is still analyzed in full — only stored outputs are scrubbed.

---

## Support

- **API Docs**: [api.safenest.dev/docs](https://api.safenest.dev/docs)
- **Discord**: [discord.gg/7kbTeRYRXD](https://discord.gg/7kbTeRYRXD)
- **Email**: support@safenest.dev
- **Issues**: [GitHub Issues](https://github.com/SafeNestSDK/unity/issues)

---

## License

MIT License - see [LICENSE.md](LICENSE.md) for details.

---

<p align="center">
  <sub>Built with care for child safety by the <a href="https://safenest.dev">SafeNest</a> team</sub>
</p>
