using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using UnityEngine;
using UnityEngine.Networking;

namespace SafeNest
{
    /// <summary>
    /// SafeNest API client for child safety analysis.
    /// </summary>
    /// <example>
    /// <code>
    /// var client = new SafeNestClient("your-api-key");
    /// var result = await client.DetectBullyingAsync("Some text to analyze");
    /// if (result.IsBullying)
    /// {
    ///     Debug.Log($"Severity: {result.Severity}");
    /// }
    /// </code>
    /// </example>
    public class SafeNestClient
    {
        private const string DefaultBaseUrl = "https://api.safenest.dev";

        private readonly string _apiKey;
        private readonly string _baseUrl;
        private readonly float _timeout;
        private readonly int _maxRetries;
        private readonly float _retryDelay;

        /// <summary>
        /// Current usage statistics (updated after each request).
        /// </summary>
        public Usage Usage { get; private set; }

        /// <summary>
        /// Request ID from the last API call.
        /// </summary>
        public string LastRequestId { get; private set; }

        /// <summary>
        /// Creates a new SafeNest client.
        /// </summary>
        /// <param name="apiKey">Your SafeNest API key.</param>
        /// <param name="timeout">Request timeout in seconds (default: 30).</param>
        /// <param name="maxRetries">Number of retry attempts (default: 3).</param>
        /// <param name="retryDelay">Initial retry delay in seconds (default: 1).</param>
        /// <param name="baseUrl">API base URL.</param>
        public SafeNestClient(
            string apiKey,
            float timeout = 30f,
            int maxRetries = 3,
            float retryDelay = 1f,
            string baseUrl = DefaultBaseUrl)
        {
            if (string.IsNullOrEmpty(apiKey))
                throw new ArgumentException("API key is required", nameof(apiKey));
            if (apiKey.Length < 10)
                throw new ArgumentException("API key appears to be invalid", nameof(apiKey));

            _apiKey = apiKey;
            _timeout = timeout;
            _maxRetries = maxRetries;
            _retryDelay = retryDelay;
            _baseUrl = baseUrl;
        }

        // =====================================================================
        // Safety Detection
        // =====================================================================

        /// <summary>
        /// Detect bullying in content.
        /// </summary>
        public async Task<BullyingResult> DetectBullyingAsync(
            string content,
            AnalysisContext context = null,
            string externalId = null,
            string customerId = null,
            Dictionary<string, object> metadata = null)
        {
            var body = new Dictionary<string, object> { { "text", content } };
            if (context != null) body["context"] = ContextToDict(context);
            if (externalId != null) body["external_id"] = externalId;
            if (customerId != null) body["customer_id"] = customerId;
            if (metadata != null) body["metadata"] = metadata;

            var response = await RequestAsync("/api/v1/safety/bullying", body);
            return ParseBullyingResult(response);
        }

        /// <summary>
        /// Detect grooming patterns in a conversation.
        /// </summary>
        public async Task<GroomingResult> DetectGroomingAsync(DetectGroomingInput input)
        {
            var messages = new List<Dictionary<string, string>>();
            foreach (var msg in input.Messages)
            {
                messages.Add(new Dictionary<string, string>
                {
                    { "sender_role", msg.Role.ToApiString() },
                    { "text", msg.Content }
                });
            }

            var body = new Dictionary<string, object> { { "messages", messages } };

            var context = new Dictionary<string, object>();
            if (input.ChildAge.HasValue) context["child_age"] = input.ChildAge.Value;
            if (input.Context != null)
            {
                foreach (var kvp in ContextToDict(input.Context))
                    context[kvp.Key] = kvp.Value;
            }
            if (context.Count > 0) body["context"] = context;

            if (input.ExternalId != null) body["external_id"] = input.ExternalId;
            if (input.CustomerId != null) body["customer_id"] = input.CustomerId;
            if (input.Metadata != null) body["metadata"] = input.Metadata;

            var response = await RequestAsync("/api/v1/safety/grooming", body);
            return ParseGroomingResult(response);
        }

        /// <summary>
        /// Detect unsafe content.
        /// </summary>
        public async Task<UnsafeResult> DetectUnsafeAsync(
            string content,
            AnalysisContext context = null,
            string externalId = null,
            string customerId = null,
            Dictionary<string, object> metadata = null)
        {
            var body = new Dictionary<string, object> { { "text", content } };
            if (context != null) body["context"] = ContextToDict(context);
            if (externalId != null) body["external_id"] = externalId;
            if (customerId != null) body["customer_id"] = customerId;
            if (metadata != null) body["metadata"] = metadata;

            var response = await RequestAsync("/api/v1/safety/unsafe", body);
            return ParseUnsafeResult(response);
        }

        /// <summary>
        /// Quick analysis - runs bullying and unsafe detection.
        /// </summary>
        public async Task<AnalyzeResult> AnalyzeAsync(
            string content,
            AnalysisContext context = null,
            List<string> include = null,
            string externalId = null,
            string customerId = null,
            Dictionary<string, object> metadata = null)
        {
            var checks = include ?? new List<string> { "bullying", "unsafe" };

            BullyingResult bullyingResult = null;
            UnsafeResult unsafeResult = null;
            float maxRiskScore = 0f;

            if (checks.Contains("bullying"))
            {
                bullyingResult = await DetectBullyingAsync(content, context, externalId, customerId, metadata);
                maxRiskScore = Math.Max(maxRiskScore, bullyingResult.RiskScore);
            }

            if (checks.Contains("unsafe"))
            {
                unsafeResult = await DetectUnsafeAsync(content, context, externalId, customerId, metadata);
                maxRiskScore = Math.Max(maxRiskScore, unsafeResult.RiskScore);
            }

            // Determine risk level
            RiskLevel riskLevel;
            if (maxRiskScore >= 0.9f) riskLevel = RiskLevel.Critical;
            else if (maxRiskScore >= 0.7f) riskLevel = RiskLevel.High;
            else if (maxRiskScore >= 0.5f) riskLevel = RiskLevel.Medium;
            else if (maxRiskScore >= 0.3f) riskLevel = RiskLevel.Low;
            else riskLevel = RiskLevel.Safe;

            // Build summary
            var findings = new List<string>();
            if (bullyingResult?.IsBullying == true)
                findings.Add($"Bullying detected ({bullyingResult.Severity.ToApiString()})");
            if (unsafeResult?.Unsafe == true)
                findings.Add($"Unsafe content: {string.Join(", ", unsafeResult.Categories)}");
            var summary = findings.Count == 0 ? "No safety concerns detected." : string.Join(". ", findings);

            // Determine action
            var actions = new List<string>();
            if (bullyingResult != null) actions.Add(bullyingResult.RecommendedAction);
            if (unsafeResult != null) actions.Add(unsafeResult.RecommendedAction);

            string recommendedAction;
            if (actions.Contains("immediate_intervention")) recommendedAction = "immediate_intervention";
            else if (actions.Contains("flag_for_moderator")) recommendedAction = "flag_for_moderator";
            else if (actions.Contains("monitor")) recommendedAction = "monitor";
            else recommendedAction = "none";

            return new AnalyzeResult
            {
                RiskLevel = riskLevel,
                RiskScore = maxRiskScore,
                Summary = summary,
                Bullying = bullyingResult,
                Unsafe = unsafeResult,
                RecommendedAction = recommendedAction,
                ExternalId = externalId,
                CustomerId = customerId,
                Metadata = metadata
            };
        }

        // =====================================================================
        // Emotion Analysis
        // =====================================================================

        /// <summary>
        /// Analyze emotions in content.
        /// </summary>
        public async Task<EmotionsResult> AnalyzeEmotionsAsync(
            string content,
            AnalysisContext context = null,
            string externalId = null,
            string customerId = null,
            Dictionary<string, object> metadata = null)
        {
            var body = new Dictionary<string, object>
            {
                { "messages", new List<Dictionary<string, string>>
                    {
                        new Dictionary<string, string> { { "sender", "user" }, { "text", content } }
                    }
                }
            };
            if (context != null) body["context"] = ContextToDict(context);
            if (externalId != null) body["external_id"] = externalId;
            if (customerId != null) body["customer_id"] = customerId;
            if (metadata != null) body["metadata"] = metadata;

            var response = await RequestAsync("/api/v1/analysis/emotions", body);
            return ParseEmotionsResult(response);
        }

        // =====================================================================
        // Guidance
        // =====================================================================

        /// <summary>
        /// Get age-appropriate action guidance.
        /// </summary>
        public async Task<ActionPlanResult> GetActionPlanAsync(GetActionPlanInput input)
        {
            var body = new Dictionary<string, object>
            {
                { "role", (input.Audience ?? Audience.Parent).ToApiString() },
                { "situation", input.Situation }
            };

            if (input.ChildAge.HasValue) body["child_age"] = input.ChildAge.Value;
            if (input.Severity.HasValue) body["severity"] = input.Severity.Value.ToApiString();
            if (input.ExternalId != null) body["external_id"] = input.ExternalId;
            if (input.CustomerId != null) body["customer_id"] = input.CustomerId;
            if (input.Metadata != null) body["metadata"] = input.Metadata;

            var response = await RequestAsync("/api/v1/guidance/action-plan", body);
            return ParseActionPlanResult(response);
        }

        // =====================================================================
        // Reports
        // =====================================================================

        /// <summary>
        /// Generate an incident report.
        /// </summary>
        public async Task<ReportResult> GenerateReportAsync(GenerateReportInput input)
        {
            var messages = new List<Dictionary<string, string>>();
            foreach (var msg in input.Messages)
            {
                messages.Add(new Dictionary<string, string>
                {
                    { "sender", msg.Sender },
                    { "text", msg.Content }
                });
            }

            var body = new Dictionary<string, object> { { "messages", messages } };

            var meta = new Dictionary<string, object>();
            if (input.ChildAge.HasValue) meta["child_age"] = input.ChildAge.Value;
            if (input.IncidentType != null) meta["type"] = input.IncidentType;
            if (meta.Count > 0) body["meta"] = meta;

            if (input.ExternalId != null) body["external_id"] = input.ExternalId;
            if (input.CustomerId != null) body["customer_id"] = input.CustomerId;
            if (input.Metadata != null) body["metadata"] = input.Metadata;

            var response = await RequestAsync("/api/v1/reports/incident", body);
            return ParseReportResult(response);
        }

        // =====================================================================
        // Account Management (GDPR)
        // =====================================================================

        /// <summary>
        /// Delete all account data (GDPR Article 17 — Right to Erasure).
        /// </summary>
        public async Task<AccountDeletionResult> DeleteAccountDataAsync()
        {
            var response = await RequestAsync("DELETE", "/api/v1/account/data");
            return new AccountDeletionResult
            {
                Message = response.ContainsKey("message") ? response["message"].ToString() : "",
                DeletedCount = response.ContainsKey("deleted_count") ? Convert.ToInt32(response["deleted_count"]) : 0
            };
        }

        /// <summary>
        /// Export all account data as JSON (GDPR Article 20 — Right to Data Portability).
        /// </summary>
        public async Task<AccountExportResult> ExportAccountDataAsync()
        {
            var response = await RequestAsync("GET", "/api/v1/account/export");
            return new AccountExportResult
            {
                UserId = response.ContainsKey("userId") ? response["userId"].ToString() : "",
                ExportedAt = response.ContainsKey("exportedAt") ? response["exportedAt"].ToString() : "",
                Data = response.ContainsKey("data") ? response["data"] as Dictionary<string, object> : new Dictionary<string, object>()
            };
        }

        // =====================================================================
        // Private Methods
        // =====================================================================

        private async Task<Dictionary<string, object>> RequestAsync(
            string path,
            Dictionary<string, object> body)
        {
            return await RequestAsync("POST", path, body);
        }

        private async Task<Dictionary<string, object>> RequestAsync(
            string method,
            string path,
            Dictionary<string, object> body = null)
        {
            Exception lastError = null;

            for (int attempt = 0; attempt < _maxRetries; attempt++)
            {
                try
                {
                    return await PerformRequestAsync(method, path, body);
                }
                catch (AuthenticationException) { throw; }
                catch (ValidationException) { throw; }
                catch (NotFoundException) { throw; }
                catch (Exception e)
                {
                    lastError = e;
                    if (attempt < _maxRetries - 1)
                    {
                        await Task.Delay((int)(_retryDelay * 1000 * (1 << attempt)));
                    }
                }
            }

            throw lastError ?? new SafeNestException("Request failed after retries");
        }

        private async Task<Dictionary<string, object>> PerformRequestAsync(
            string method,
            string path,
            Dictionary<string, object> body)
        {
            var url = _baseUrl + path;

            using var request = new UnityWebRequest(url, method);
            if (body != null)
            {
                var json = SerializeToJson(body);
                request.uploadHandler = new UploadHandlerRaw(Encoding.UTF8.GetBytes(json));
            }
            request.downloadHandler = new DownloadHandlerBuffer();
            request.SetRequestHeader("Authorization", $"Bearer {_apiKey}");
            request.SetRequestHeader("Content-Type", "application/json");
            request.timeout = (int)_timeout;

            var operation = request.SendWebRequest();
            while (!operation.isDone)
                await Task.Yield();

            // Extract headers
            LastRequestId = request.GetResponseHeader("x-request-id");

            // Monthly usage headers
            var limitStr = request.GetResponseHeader("x-monthly-limit");
            var usedStr = request.GetResponseHeader("x-monthly-used");
            var remainingStr = request.GetResponseHeader("x-monthly-remaining");

            if (int.TryParse(limitStr, out int limit) &&
                int.TryParse(usedStr, out int used) &&
                int.TryParse(remainingStr, out int remaining))
            {
                Usage = new Usage { Limit = limit, Used = used, Remaining = remaining };
            }

            if (request.result == UnityWebRequest.Result.ConnectionError)
                throw new NetworkException(request.error);

            if (request.result == UnityWebRequest.Result.ProtocolError)
                HandleErrorResponse(request);

            var responseJson = request.downloadHandler.text;
            return ParseJson(responseJson);
        }

        private void HandleErrorResponse(UnityWebRequest request)
        {
            string message = "Request failed";
            object details = null;

            try
            {
                var data = ParseJson(request.downloadHandler.text);
                if (data.TryGetValue("error", out var errorObj) && errorObj is Dictionary<string, object> error)
                {
                    if (error.TryGetValue("message", out var msg))
                        message = msg.ToString();
                    error.TryGetValue("details", out details);
                }
            }
            catch { }

            var status = (int)request.responseCode;

            throw status switch
            {
                400 => new ValidationException(message, details),
                401 => new AuthenticationException(message, details),
                404 => new NotFoundException(message, details),
                429 => new RateLimitException(message, details),
                >= 500 => new ServerException(message, status, details),
                _ => new SafeNestException(message, details)
            };
        }

        private Dictionary<string, object> ContextToDict(AnalysisContext context)
        {
            var dict = new Dictionary<string, object>();
            if (!string.IsNullOrEmpty(context.Language)) dict["language"] = context.Language;
            if (!string.IsNullOrEmpty(context.AgeGroup)) dict["age_group"] = context.AgeGroup;
            if (!string.IsNullOrEmpty(context.Relationship)) dict["relationship"] = context.Relationship;
            if (!string.IsNullOrEmpty(context.Platform)) dict["platform"] = context.Platform;
            return dict;
        }

        // Simple JSON serialization (Unity's JsonUtility doesn't handle dictionaries well)
        private string SerializeToJson(Dictionary<string, object> dict)
        {
            var sb = new StringBuilder();
            sb.Append("{");
            var first = true;
            foreach (var kvp in dict)
            {
                if (!first) sb.Append(",");
                first = false;
                sb.Append($"\"{kvp.Key}\":");
                sb.Append(SerializeValue(kvp.Value));
            }
            sb.Append("}");
            return sb.ToString();
        }

        private string SerializeValue(object value)
        {
            if (value == null) return "null";
            if (value is string s) return $"\"{EscapeString(s)}\"";
            if (value is bool b) return b ? "true" : "false";
            if (value is int or long or float or double) return value.ToString();
            if (value is Dictionary<string, object> dict) return SerializeToJson(dict);
            if (value is Dictionary<string, string> sdict)
            {
                var sb = new StringBuilder("{");
                var first = true;
                foreach (var kvp in sdict)
                {
                    if (!first) sb.Append(",");
                    first = false;
                    sb.Append($"\"{kvp.Key}\":\"{EscapeString(kvp.Value)}\"");
                }
                sb.Append("}");
                return sb.ToString();
            }
            if (value is IList<Dictionary<string, string>> list)
            {
                var sb = new StringBuilder("[");
                for (int i = 0; i < list.Count; i++)
                {
                    if (i > 0) sb.Append(",");
                    sb.Append(SerializeValue(list[i]));
                }
                sb.Append("]");
                return sb.ToString();
            }
            return $"\"{value}\"";
        }

        private string EscapeString(string s)
        {
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r");
        }

        // Simple JSON parsing
        private Dictionary<string, object> ParseJson(string json)
        {
            // For production, consider using a proper JSON library like Newtonsoft.Json
            // This is a simplified parser for basic responses
            return MiniJson.Deserialize(json) as Dictionary<string, object> ?? new Dictionary<string, object>();
        }

        private BullyingResult ParseBullyingResult(Dictionary<string, object> data)
        {
            return new BullyingResult
            {
                IsBullying = GetBool(data, "is_bullying"),
                Severity = EnumExtensions.ParseSeverity(GetString(data, "severity")),
                BullyingType = GetStringList(data, "bullying_type"),
                Confidence = GetFloat(data, "confidence"),
                Rationale = GetString(data, "rationale"),
                RiskScore = GetFloat(data, "risk_score"),
                RecommendedAction = GetString(data, "recommended_action"),
                ExternalId = GetString(data, "external_id"),
                CustomerId = GetString(data, "customer_id"),
                Metadata = GetDict(data, "metadata")
            };
        }

        private GroomingResult ParseGroomingResult(Dictionary<string, object> data)
        {
            return new GroomingResult
            {
                GroomingRisk = EnumExtensions.ParseGroomingRisk(GetString(data, "grooming_risk")),
                Flags = GetStringList(data, "flags"),
                Confidence = GetFloat(data, "confidence"),
                Rationale = GetString(data, "rationale"),
                RiskScore = GetFloat(data, "risk_score"),
                RecommendedAction = GetString(data, "recommended_action"),
                ExternalId = GetString(data, "external_id"),
                CustomerId = GetString(data, "customer_id"),
                Metadata = GetDict(data, "metadata")
            };
        }

        private UnsafeResult ParseUnsafeResult(Dictionary<string, object> data)
        {
            return new UnsafeResult
            {
                Unsafe = GetBool(data, "unsafe"),
                Categories = GetStringList(data, "categories"),
                Severity = EnumExtensions.ParseSeverity(GetString(data, "severity")),
                Confidence = GetFloat(data, "confidence"),
                Rationale = GetString(data, "rationale"),
                RiskScore = GetFloat(data, "risk_score"),
                RecommendedAction = GetString(data, "recommended_action"),
                ExternalId = GetString(data, "external_id"),
                CustomerId = GetString(data, "customer_id"),
                Metadata = GetDict(data, "metadata")
            };
        }

        private EmotionsResult ParseEmotionsResult(Dictionary<string, object> data)
        {
            return new EmotionsResult
            {
                DominantEmotions = GetStringList(data, "dominant_emotions"),
                Trend = EnumExtensions.ParseEmotionTrend(GetString(data, "trend")),
                Intensity = GetFloat(data, "intensity"),
                ConcerningPatterns = GetStringList(data, "concerning_patterns"),
                RecommendedFollowup = GetString(data, "recommended_followup"),
                ExternalId = GetString(data, "external_id"),
                CustomerId = GetString(data, "customer_id"),
                Metadata = GetDict(data, "metadata")
            };
        }

        private ActionPlanResult ParseActionPlanResult(Dictionary<string, object> data)
        {
            return new ActionPlanResult
            {
                Steps = GetStringList(data, "steps"),
                Tone = GetString(data, "tone"),
                Resources = GetStringList(data, "resources"),
                Urgency = GetString(data, "urgency"),
                ExternalId = GetString(data, "external_id"),
                CustomerId = GetString(data, "customer_id"),
                Metadata = GetDict(data, "metadata")
            };
        }

        private ReportResult ParseReportResult(Dictionary<string, object> data)
        {
            return new ReportResult
            {
                Summary = GetString(data, "summary"),
                RiskLevel = EnumExtensions.ParseRiskLevel(GetString(data, "risk_level")),
                Timeline = GetStringList(data, "timeline"),
                KeyEvidence = GetStringList(data, "key_evidence"),
                RecommendedNextSteps = GetStringList(data, "recommended_next_steps"),
                ExternalId = GetString(data, "external_id"),
                CustomerId = GetString(data, "customer_id"),
                Metadata = GetDict(data, "metadata")
            };
        }

        private static string GetString(Dictionary<string, object> data, string key)
        {
            return data.TryGetValue(key, out var value) ? value?.ToString() : null;
        }

        private static bool GetBool(Dictionary<string, object> data, string key)
        {
            if (data.TryGetValue(key, out var value))
            {
                if (value is bool b) return b;
                if (bool.TryParse(value?.ToString(), out var parsed)) return parsed;
            }
            return false;
        }

        private static float GetFloat(Dictionary<string, object> data, string key)
        {
            if (data.TryGetValue(key, out var value))
            {
                if (value is float f) return f;
                if (value is double d) return (float)d;
                if (float.TryParse(value?.ToString(), out var parsed)) return parsed;
            }
            return 0f;
        }

        private static List<string> GetStringList(Dictionary<string, object> data, string key)
        {
            var list = new List<string>();
            if (data.TryGetValue(key, out var value) && value is IList<object> items)
            {
                foreach (var item in items)
                    list.Add(item?.ToString() ?? "");
            }
            return list;
        }

        private static Dictionary<string, object> GetDict(Dictionary<string, object> data, string key)
        {
            if (data.TryGetValue(key, out var value) && value is Dictionary<string, object> dict)
                return dict;
            return null;
        }

        [Serializable]
        private class JsonWrapper
        {
            public Dictionary<string, object> data;
        }
    }
}
