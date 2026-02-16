using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using UnityEngine;
using UnityEngine.Networking;

namespace Tuteliq
{
    /// <summary>
    /// Tuteliq API client for child safety analysis.
    /// </summary>
    /// <example>
    /// <code>
    /// var client = new TuteliqClient("your-api-key");
    /// var result = await client.DetectBullyingAsync("Some text to analyze");
    /// if (result.IsBullying)
    /// {
    ///     Debug.Log($"Severity: {result.Severity}");
    /// }
    /// </code>
    /// </example>
    public class TuteliqClient
    {
        private const string DefaultBaseUrl = "https://api.tuteliq.ai";
        private const string SdkIdentifier = "Unity SDK";

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
        /// Creates a new Tuteliq client.
        /// </summary>
        /// <param name="apiKey">Your Tuteliq API key.</param>
        /// <param name="timeout">Request timeout in seconds (default: 30).</param>
        /// <param name="maxRetries">Number of retry attempts (default: 3).</param>
        /// <param name="retryDelay">Initial retry delay in seconds (default: 1).</param>
        /// <param name="baseUrl">API base URL.</param>
        public TuteliqClient(
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
            if (context != null)
                body["context"] = ContextToDict(context);
            else
                body["context"] = new Dictionary<string, object> { { "platform", ResolvePlatform() } };
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
            if (!context.ContainsKey("platform"))
                context["platform"] = ResolvePlatform();
            body["context"] = context;

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
            if (context != null)
                body["context"] = ContextToDict(context);
            else
                body["context"] = new Dictionary<string, object> { { "platform", ResolvePlatform() } };
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

            int? totalCredits = null;
            if (bullyingResult?.CreditsUsed != null || unsafeResult?.CreditsUsed != null)
                totalCredits = (bullyingResult?.CreditsUsed ?? 0) + (unsafeResult?.CreditsUsed ?? 0);

            return new AnalyzeResult
            {
                RiskLevel = riskLevel,
                RiskScore = maxRiskScore,
                Summary = summary,
                Bullying = bullyingResult,
                Unsafe = unsafeResult,
                RecommendedAction = recommendedAction,
                CreditsUsed = totalCredits,
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
            if (context != null)
                body["context"] = ContextToDict(context);
            else
                body["context"] = new Dictionary<string, object> { { "platform", ResolvePlatform() } };
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
                { "situation", input.Situation },
                { "context", new Dictionary<string, object> { { "platform", ResolvePlatform() } } }
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

            body["context"] = new Dictionary<string, object> { { "platform", ResolvePlatform() } };

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

        /// <summary>
        /// Record user consent (GDPR Article 7).
        /// </summary>
        public async Task<ConsentActionResult> RecordConsentAsync(RecordConsentInput input)
        {
            var body = new Dictionary<string, object>
            {
                { "consent_type", input.ConsentType },
                { "version", input.Version },
                { "context", new Dictionary<string, object> { { "platform", ResolvePlatform() } } }
            };
            var response = await RequestAsync("POST", "/api/v1/account/consent", body);
            return ParseConsentActionResult(response);
        }

        /// <summary>
        /// Get current consent status (GDPR Article 7).
        /// </summary>
        public async Task<ConsentStatusResult> GetConsentStatusAsync(string consentType = null)
        {
            var query = consentType != null ? $"?type={consentType}" : "";
            var response = await RequestAsync("GET", $"/api/v1/account/consent{query}");
            var consents = new List<ConsentRecord>();
            if (response.ContainsKey("consents") && response["consents"] is List<object> list)
            {
                foreach (var item in list)
                {
                    if (item is Dictionary<string, object> dict)
                        consents.Add(ParseConsentRecord(dict));
                }
            }
            return new ConsentStatusResult { Consents = consents };
        }

        /// <summary>
        /// Withdraw consent (GDPR Article 7.3).
        /// </summary>
        public async Task<ConsentActionResult> WithdrawConsentAsync(string consentType)
        {
            var response = await RequestAsync("DELETE", $"/api/v1/account/consent/{consentType}");
            return ParseConsentActionResult(response);
        }

        /// <summary>
        /// Rectify user data (GDPR Article 16 — Right to Rectification).
        /// </summary>
        public async Task<RectifyDataResult> RectifyDataAsync(RectifyDataInput input)
        {
            var body = new Dictionary<string, object>
            {
                { "collection", input.Collection },
                { "document_id", input.DocumentId },
                { "fields", input.Fields },
                { "context", new Dictionary<string, object> { { "platform", ResolvePlatform() } } }
            };
            var response = await RequestAsync("PATCH", "/api/v1/account/data", body);
            var updatedFields = new List<string>();
            if (response.ContainsKey("updated_fields") && response["updated_fields"] is List<object> list)
            {
                foreach (var item in list) updatedFields.Add(item.ToString());
            }
            return new RectifyDataResult
            {
                Message = response.ContainsKey("message") ? response["message"].ToString() : "",
                UpdatedFields = updatedFields
            };
        }

        /// <summary>
        /// Get audit logs (GDPR Article 15 — Right of Access).
        /// </summary>
        public async Task<AuditLogsResult> GetAuditLogsAsync(string action = null, int? limit = null)
        {
            var parameters = new List<string>();
            if (action != null) parameters.Add($"action={action}");
            if (limit.HasValue) parameters.Add($"limit={limit.Value}");
            var query = parameters.Count > 0 ? $"?{string.Join("&", parameters)}" : "";
            var response = await RequestAsync("GET", $"/api/v1/account/audit-logs{query}");
            var logs = new List<AuditLogEntry>();
            if (response.ContainsKey("audit_logs") && response["audit_logs"] is List<object> list)
            {
                foreach (var item in list)
                {
                    if (item is Dictionary<string, object> dict)
                    {
                        logs.Add(new AuditLogEntry
                        {
                            Id = dict.ContainsKey("id") ? dict["id"].ToString() : "",
                            UserId = dict.ContainsKey("user_id") ? dict["user_id"].ToString() : "",
                            Action = dict.ContainsKey("action") ? dict["action"].ToString() : "",
                            CreatedAt = dict.ContainsKey("created_at") ? dict["created_at"].ToString() : "",
                        });
                    }
                }
            }
            return new AuditLogsResult { AuditLogs = logs };
        }

        // =====================================================================
        // Breach Management (GDPR Article 33/34)
        // =====================================================================

        /// <summary>
        /// Log a new data breach.
        /// </summary>
        public async Task<LogBreachResult> LogBreachAsync(LogBreachInput input)
        {
            var body = new Dictionary<string, object>
            {
                { "title", input.Title },
                { "description", input.Description },
                { "severity", input.Severity },
                { "affected_user_ids", input.AffectedUserIds },
                { "data_categories", input.DataCategories },
                { "reported_by", input.ReportedBy },
                { "context", new Dictionary<string, object> { { "platform", ResolvePlatform() } } }
            };
            var response = await RequestAsync("/api/v1/admin/breach", body);
            return new LogBreachResult
            {
                Message = GetString(response, "message"),
                Breach = ParseBreachRecord(response.ContainsKey("breach") && response["breach"] is Dictionary<string, object> d ? d : new Dictionary<string, object>())
            };
        }

        /// <summary>
        /// List data breaches.
        /// </summary>
        public async Task<BreachListResult> ListBreachesAsync(string status = null, int? limit = null)
        {
            var parameters = new List<string>();
            if (status != null) parameters.Add($"status={status}");
            if (limit.HasValue) parameters.Add($"limit={limit.Value}");
            var query = parameters.Count > 0 ? $"?{string.Join("&", parameters)}" : "";
            var response = await RequestAsync("GET", $"/api/v1/admin/breach{query}");
            var breaches = new List<BreachRecord>();
            if (response.ContainsKey("breaches") && response["breaches"] is List<object> list)
            {
                foreach (var item in list)
                {
                    if (item is Dictionary<string, object> dict)
                        breaches.Add(ParseBreachRecord(dict));
                }
            }
            return new BreachListResult { Breaches = breaches };
        }

        /// <summary>
        /// Get a single breach by ID.
        /// </summary>
        public async Task<BreachResult> GetBreachAsync(string id)
        {
            var response = await RequestAsync("GET", $"/api/v1/admin/breach/{id}");
            return new BreachResult
            {
                Breach = ParseBreachRecord(response.ContainsKey("breach") && response["breach"] is Dictionary<string, object> d ? d : new Dictionary<string, object>())
            };
        }

        /// <summary>
        /// Update a breach's status.
        /// </summary>
        public async Task<BreachResult> UpdateBreachStatusAsync(string id, UpdateBreachInput input)
        {
            var body = new Dictionary<string, object> { { "status", input.Status } };
            if (input.NotificationStatus != null) body["notification_status"] = input.NotificationStatus;
            if (input.Notes != null) body["notes"] = input.Notes;
            body["context"] = new Dictionary<string, object> { { "platform", ResolvePlatform() } };
            var response = await RequestAsync("PATCH", $"/api/v1/admin/breach/{id}", body);
            return new BreachResult
            {
                Breach = ParseBreachRecord(response.ContainsKey("breach") && response["breach"] is Dictionary<string, object> d ? d : new Dictionary<string, object>())
            };
        }

        private BreachRecord ParseBreachRecord(Dictionary<string, object> data)
        {
            return new BreachRecord
            {
                Id = GetString(data, "id"),
                Title = GetString(data, "title"),
                Description = GetString(data, "description"),
                Severity = GetString(data, "severity"),
                Status = GetString(data, "status"),
                NotificationStatus = GetString(data, "notification_status"),
                AffectedUserIds = GetStringList(data, "affected_user_ids"),
                DataCategories = GetStringList(data, "data_categories"),
                ReportedBy = GetString(data, "reported_by"),
                NotificationDeadline = GetString(data, "notification_deadline"),
                CreatedAt = GetString(data, "created_at"),
                UpdatedAt = GetString(data, "updated_at"),
            };
        }

        private ConsentActionResult ParseConsentActionResult(Dictionary<string, object> response)
        {
            var result = new ConsentActionResult
            {
                Message = response.ContainsKey("message") ? response["message"].ToString() : "",
            };
            if (response.ContainsKey("consent") && response["consent"] is Dictionary<string, object> dict)
            {
                result.Consent = ParseConsentRecord(dict);
            }
            return result;
        }

        private ConsentRecord ParseConsentRecord(Dictionary<string, object> dict)
        {
            return new ConsentRecord
            {
                Id = dict.ContainsKey("id") ? dict["id"].ToString() : "",
                UserId = dict.ContainsKey("user_id") ? dict["user_id"].ToString() : "",
                ConsentType = dict.ContainsKey("consent_type") ? dict["consent_type"].ToString() : "",
                Status = dict.ContainsKey("status") ? dict["status"].ToString() : "",
                Version = dict.ContainsKey("version") ? dict["version"].ToString() : "",
                CreatedAt = dict.ContainsKey("created_at") ? dict["created_at"].ToString() : "",
            };
        }

        // =====================================================================
        // Voice Analysis
        // =====================================================================

        /// <summary>
        /// Analyze voice/audio content for safety concerns.
        /// </summary>
        public async Task<VoiceAnalysisResult> AnalyzeVoiceAsync(
            byte[] file,
            string filename,
            string analysisType = "all",
            string fileId = null,
            string externalId = null,
            string customerId = null,
            Dictionary<string, object> metadata = null,
            string ageGroup = null,
            string language = null,
            string platform = null,
            int? childAge = null)
        {
            var formSections = new List<IMultipartFormSection>();
            formSections.Add(new MultipartFormFileSection("file", file, filename, "application/octet-stream"));
            formSections.Add(new MultipartFormDataSection("analysis_type", analysisType));
            formSections.Add(new MultipartFormDataSection("platform", ResolvePlatform(platform)));
            if (fileId != null) formSections.Add(new MultipartFormDataSection("file_id", fileId));
            if (externalId != null) formSections.Add(new MultipartFormDataSection("external_id", externalId));
            if (customerId != null) formSections.Add(new MultipartFormDataSection("customer_id", customerId));
            if (metadata != null) formSections.Add(new MultipartFormDataSection("metadata", MiniJson.Serialize(metadata)));
            if (ageGroup != null) formSections.Add(new MultipartFormDataSection("age_group", ageGroup));
            if (language != null) formSections.Add(new MultipartFormDataSection("language", language));
            if (childAge.HasValue) formSections.Add(new MultipartFormDataSection("child_age", childAge.Value.ToString()));

            var data = await MultipartRequestAsync("/api/v1/safety/voice", formSections);
            return ParseVoiceAnalysisResult(data);
        }

        // =====================================================================
        // Image Analysis
        // =====================================================================

        /// <summary>
        /// Analyze image content for safety concerns.
        /// </summary>
        public async Task<ImageAnalysisResult> AnalyzeImageAsync(
            byte[] file,
            string filename,
            string analysisType = "all",
            string fileId = null,
            string externalId = null,
            string customerId = null,
            Dictionary<string, object> metadata = null,
            string ageGroup = null,
            string language = null,
            string platform = null,
            int? childAge = null)
        {
            var formSections = new List<IMultipartFormSection>();
            formSections.Add(new MultipartFormFileSection("file", file, filename, "application/octet-stream"));
            formSections.Add(new MultipartFormDataSection("analysis_type", analysisType));
            formSections.Add(new MultipartFormDataSection("platform", ResolvePlatform(platform)));
            if (fileId != null) formSections.Add(new MultipartFormDataSection("file_id", fileId));
            if (externalId != null) formSections.Add(new MultipartFormDataSection("external_id", externalId));
            if (customerId != null) formSections.Add(new MultipartFormDataSection("customer_id", customerId));
            if (metadata != null) formSections.Add(new MultipartFormDataSection("metadata", MiniJson.Serialize(metadata)));
            if (ageGroup != null) formSections.Add(new MultipartFormDataSection("age_group", ageGroup));
            if (language != null) formSections.Add(new MultipartFormDataSection("language", language));
            if (childAge.HasValue) formSections.Add(new MultipartFormDataSection("child_age", childAge.Value.ToString()));

            var data = await MultipartRequestAsync("/api/v1/safety/image", formSections);
            return ParseImageAnalysisResult(data);
        }

        // =====================================================================
        // Webhooks
        // =====================================================================

        /// <summary>
        /// List all webhooks.
        /// </summary>
        public async Task<WebhookListResult> ListWebhooksAsync()
        {
            var response = await RequestAsync("GET", "/api/v1/webhooks");
            return ParseWebhookListResult(response);
        }

        /// <summary>
        /// Create a new webhook.
        /// </summary>
        public async Task<CreateWebhookResult> CreateWebhookAsync(CreateWebhookInput input)
        {
            var body = new Dictionary<string, object>
            {
                { "url", input.Url },
                { "events", input.Events },
                { "active", input.Active },
                { "context", new Dictionary<string, object> { { "platform", ResolvePlatform() } } }
            };
            var response = await RequestAsync("POST", "/api/v1/webhooks", body);
            return ParseCreateWebhookResult(response);
        }

        /// <summary>
        /// Update an existing webhook.
        /// </summary>
        public async Task<UpdateWebhookResult> UpdateWebhookAsync(string webhookId, UpdateWebhookInput input)
        {
            var body = new Dictionary<string, object>();
            if (input.Url != null) body["url"] = input.Url;
            if (input.Events != null) body["events"] = input.Events;
            if (input.Active.HasValue) body["active"] = input.Active.Value;
            body["context"] = new Dictionary<string, object> { { "platform", ResolvePlatform() } };
            var response = await RequestAsync("PATCH", $"/api/v1/webhooks/{webhookId}", body);
            return ParseUpdateWebhookResult(response);
        }

        /// <summary>
        /// Delete a webhook.
        /// </summary>
        public async Task<DeleteWebhookResult> DeleteWebhookAsync(string webhookId)
        {
            var response = await RequestAsync("DELETE", $"/api/v1/webhooks/{webhookId}");
            return new DeleteWebhookResult
            {
                Message = GetString(response, "message")
            };
        }

        /// <summary>
        /// Test a webhook by sending a test event.
        /// </summary>
        public async Task<TestWebhookResult> TestWebhookAsync(string webhookId)
        {
            var body = new Dictionary<string, object>
            {
                { "context", new Dictionary<string, object> { { "platform", ResolvePlatform() } } }
            };
            var response = await RequestAsync("POST", $"/api/v1/webhooks/{webhookId}/test", body);
            return new TestWebhookResult
            {
                Message = GetString(response, "message"),
                StatusCode = response.ContainsKey("status_code") ? (int?)Convert.ToInt32(response["status_code"]) : null
            };
        }

        /// <summary>
        /// Regenerate the secret for a webhook.
        /// </summary>
        public async Task<RegenerateSecretResult> RegenerateWebhookSecretAsync(string webhookId)
        {
            var body = new Dictionary<string, object>
            {
                { "context", new Dictionary<string, object> { { "platform", ResolvePlatform() } } }
            };
            var response = await RequestAsync("POST", $"/api/v1/webhooks/{webhookId}/secret", body);
            return new RegenerateSecretResult
            {
                Message = GetString(response, "message"),
                Secret = GetString(response, "secret")
            };
        }

        // =====================================================================
        // Pricing
        // =====================================================================

        /// <summary>
        /// Get pricing plans overview.
        /// </summary>
        public async Task<PricingResult> GetPricingAsync()
        {
            var response = await RequestAsync("GET", "/api/v1/pricing");
            return ParsePricingResult(response);
        }

        /// <summary>
        /// Get detailed pricing information.
        /// </summary>
        public async Task<PricingDetailsResult> GetPricingDetailsAsync()
        {
            var response = await RequestAsync("GET", "/api/v1/pricing/details");
            return ParsePricingDetailsResult(response);
        }

        // =====================================================================
        // Usage
        // =====================================================================

        /// <summary>
        /// Get usage history for the API key.
        /// </summary>
        public async Task<UsageHistoryResult> GetUsageHistoryAsync(int? days = null)
        {
            var query = days.HasValue ? $"?days={days.Value}" : "";
            var response = await RequestAsync("GET", $"/api/v1/usage/history{query}");
            return ParseUsageHistoryResult(response);
        }

        /// <summary>
        /// Get usage breakdown by tool/endpoint.
        /// </summary>
        public async Task<UsageByToolResult> GetUsageByToolAsync(string date = null)
        {
            var query = date != null ? $"?date={date}" : "";
            var response = await RequestAsync("GET", $"/api/v1/usage/tools{query}");
            return ParseUsageByToolResult(response);
        }

        /// <summary>
        /// Get monthly usage summary.
        /// </summary>
        public async Task<UsageMonthlyResult> GetUsageMonthlyAsync()
        {
            var response = await RequestAsync("GET", "/api/v1/usage/monthly");
            return ParseUsageMonthlyResult(response);
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
                catch (QuotaExceededException) { throw; }
                catch (TierAccessException) { throw; }
                catch (Exception e)
                {
                    lastError = e;
                    if (attempt < _maxRetries - 1)
                    {
                        await Task.Delay((int)(_retryDelay * 1000 * (1 << attempt)));
                    }
                }
            }

            throw lastError ?? new TuteliqException("Request failed after retries");
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
                402 => new QuotaExceededException(message, details),
                403 => new TierAccessException(message, details),
                404 => new NotFoundException(message, details),
                429 => new RateLimitException(message, details),
                >= 500 => new ServerException(message, status, details),
                _ => new TuteliqException(message, details)
            };
        }

        private async Task<Dictionary<string, object>> MultipartRequestAsync(
            string path,
            List<IMultipartFormSection> formSections)
        {
            Exception lastError = null;

            for (int attempt = 0; attempt < _maxRetries; attempt++)
            {
                try
                {
                    return await PerformMultipartRequestAsync(path, formSections);
                }
                catch (AuthenticationException) { throw; }
                catch (ValidationException) { throw; }
                catch (NotFoundException) { throw; }
                catch (QuotaExceededException) { throw; }
                catch (TierAccessException) { throw; }
                catch (Exception e)
                {
                    lastError = e;
                    if (attempt < _maxRetries - 1)
                    {
                        await Task.Delay((int)(_retryDelay * 1000 * (1 << attempt)));
                    }
                }
            }

            throw lastError ?? new TuteliqException("Request failed after retries");
        }

        private async Task<Dictionary<string, object>> PerformMultipartRequestAsync(
            string path,
            List<IMultipartFormSection> formSections)
        {
            var url = _baseUrl + path;

            var boundary = UnityWebRequest.GenerateBoundary();
            var formData = UnityWebRequest.SerializeFormSections(formSections, boundary);

            using var request = new UnityWebRequest(url, "POST");
            request.uploadHandler = new UploadHandlerRaw(formData);
            request.downloadHandler = new DownloadHandlerBuffer();
            request.SetRequestHeader("Authorization", $"Bearer {_apiKey}");
            request.SetRequestHeader("Content-Type", $"multipart/form-data; boundary={Encoding.UTF8.GetString(boundary)}");
            request.timeout = (int)_timeout;

            var operation = request.SendWebRequest();
            while (!operation.isDone)
                await Task.Yield();

            LastRequestId = request.GetResponseHeader("x-request-id");

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

        private static string ResolvePlatform(string platform = null)
        {
            if (!string.IsNullOrEmpty(platform))
                return $"{platform} - {SdkIdentifier}";
            return SdkIdentifier;
        }

        private Dictionary<string, object> ContextToDict(AnalysisContext context)
        {
            var dict = new Dictionary<string, object>();
            if (!string.IsNullOrEmpty(context.Language)) dict["language"] = context.Language;
            if (!string.IsNullOrEmpty(context.AgeGroup)) dict["age_group"] = context.AgeGroup;
            if (!string.IsNullOrEmpty(context.Relationship)) dict["relationship"] = context.Relationship;
            dict["platform"] = ResolvePlatform(context.Platform);
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
                CreditsUsed = GetNullableInt(data, "credits_used"),
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
                CreditsUsed = GetNullableInt(data, "credits_used"),
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
                CreditsUsed = GetNullableInt(data, "credits_used"),
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
                CreditsUsed = GetNullableInt(data, "credits_used"),
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
                CreditsUsed = GetNullableInt(data, "credits_used"),
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
                CreditsUsed = GetNullableInt(data, "credits_used"),
                ExternalId = GetString(data, "external_id"),
                CustomerId = GetString(data, "customer_id"),
                Metadata = GetDict(data, "metadata")
            };
        }

        private VoiceAnalysisResult ParseVoiceAnalysisResult(Dictionary<string, object> data)
        {
            var result = new VoiceAnalysisResult
            {
                FileId = GetString(data, "file_id"),
                Analysis = GetDict(data, "analysis"),
                OverallRiskScore = GetNullableDouble(data, "overall_risk_score"),
                OverallSeverity = GetString(data, "overall_severity"),
                CreditsUsed = GetNullableInt(data, "credits_used"),
                ExternalId = GetString(data, "external_id"),
                CustomerId = GetString(data, "customer_id"),
                Metadata = GetDict(data, "metadata")
            };

            if (data.ContainsKey("transcription") && data["transcription"] is Dictionary<string, object> transDict)
            {
                result.Transcription = new TranscriptionResult
                {
                    Text = GetString(transDict, "text"),
                    Language = GetString(transDict, "language"),
                    Duration = GetNullableDouble(transDict, "duration"),
                    Segments = ParseTranscriptionSegments(transDict)
                };
            }

            return result;
        }

        private List<TranscriptionSegment> ParseTranscriptionSegments(Dictionary<string, object> data)
        {
            var segments = new List<TranscriptionSegment>();
            if (data.ContainsKey("segments") && data["segments"] is IList<object> list)
            {
                foreach (var item in list)
                {
                    if (item is Dictionary<string, object> seg)
                    {
                        segments.Add(new TranscriptionSegment
                        {
                            Start = GetDouble(seg, "start"),
                            End = GetDouble(seg, "end"),
                            Text = GetString(seg, "text")
                        });
                    }
                }
            }
            return segments;
        }

        private ImageAnalysisResult ParseImageAnalysisResult(Dictionary<string, object> data)
        {
            var result = new ImageAnalysisResult
            {
                FileId = GetString(data, "file_id"),
                TextAnalysis = GetDict(data, "text_analysis"),
                OverallRiskScore = GetNullableDouble(data, "overall_risk_score"),
                OverallSeverity = GetString(data, "overall_severity"),
                CreditsUsed = GetNullableInt(data, "credits_used"),
                ExternalId = GetString(data, "external_id"),
                CustomerId = GetString(data, "customer_id"),
                Metadata = GetDict(data, "metadata")
            };

            if (data.ContainsKey("vision") && data["vision"] is Dictionary<string, object> visionDict)
            {
                result.Vision = new VisionResult
                {
                    ExtractedText = GetString(visionDict, "extracted_text"),
                    VisualCategories = GetStringList(visionDict, "visual_categories"),
                    VisualSeverity = GetString(visionDict, "visual_severity"),
                    VisualConfidence = GetNullableDouble(visionDict, "visual_confidence"),
                    VisualDescription = GetString(visionDict, "visual_description"),
                    ContainsText = GetNullableBool(visionDict, "contains_text"),
                    ContainsFaces = GetNullableBool(visionDict, "contains_faces")
                };
            }

            return result;
        }

        private WebhookInfo ParseWebhookInfo(Dictionary<string, object> data)
        {
            return new WebhookInfo
            {
                Id = GetString(data, "id"),
                Url = GetString(data, "url"),
                Events = GetStringList(data, "events"),
                Active = GetBool(data, "active"),
                Secret = GetString(data, "secret"),
                CreatedAt = GetString(data, "created_at"),
                UpdatedAt = GetString(data, "updated_at")
            };
        }

        private WebhookListResult ParseWebhookListResult(Dictionary<string, object> data)
        {
            var webhooks = new List<WebhookInfo>();
            if (data.ContainsKey("webhooks") && data["webhooks"] is IList<object> list)
            {
                foreach (var item in list)
                {
                    if (item is Dictionary<string, object> dict)
                        webhooks.Add(ParseWebhookInfo(dict));
                }
            }
            return new WebhookListResult { Webhooks = webhooks };
        }

        private CreateWebhookResult ParseCreateWebhookResult(Dictionary<string, object> data)
        {
            var result = new CreateWebhookResult
            {
                Message = GetString(data, "message")
            };
            if (data.ContainsKey("webhook") && data["webhook"] is Dictionary<string, object> dict)
                result.Webhook = ParseWebhookInfo(dict);
            return result;
        }

        private UpdateWebhookResult ParseUpdateWebhookResult(Dictionary<string, object> data)
        {
            var result = new UpdateWebhookResult
            {
                Message = GetString(data, "message")
            };
            if (data.ContainsKey("webhook") && data["webhook"] is Dictionary<string, object> dict)
                result.Webhook = ParseWebhookInfo(dict);
            return result;
        }

        private PricingResult ParsePricingResult(Dictionary<string, object> data)
        {
            var plans = new List<PricingPlan>();
            if (data.ContainsKey("plans") && data["plans"] is IList<object> list)
            {
                foreach (var item in list)
                {
                    if (item is Dictionary<string, object> dict)
                    {
                        plans.Add(new PricingPlan
                        {
                            Name = GetString(dict, "name"),
                            Price = GetString(dict, "price"),
                            Messages = GetString(dict, "messages"),
                            Features = GetStringList(dict, "features")
                        });
                    }
                }
            }
            return new PricingResult { Plans = plans };
        }

        private PricingDetailsResult ParsePricingDetailsResult(Dictionary<string, object> data)
        {
            var plans = new List<PricingDetailPlan>();
            if (data.ContainsKey("plans") && data["plans"] is IList<object> list)
            {
                foreach (var item in list)
                {
                    if (item is Dictionary<string, object> dict)
                    {
                        plans.Add(new PricingDetailPlan
                        {
                            Name = GetString(dict, "name"),
                            Tier = GetString(dict, "tier"),
                            Price = GetDict(dict, "price"),
                            Limits = GetDict(dict, "limits"),
                            Features = GetDict(dict, "features"),
                            Endpoints = GetStringList(dict, "endpoints")
                        });
                    }
                }
            }
            return new PricingDetailsResult { Plans = plans };
        }

        private UsageHistoryResult ParseUsageHistoryResult(Dictionary<string, object> data)
        {
            var days = new List<UsageDay>();
            if (data.ContainsKey("days") && data["days"] is IList<object> list)
            {
                foreach (var item in list)
                {
                    if (item is Dictionary<string, object> dict)
                    {
                        days.Add(new UsageDay
                        {
                            Date = GetString(dict, "date"),
                            TotalRequests = GetInt(dict, "total_requests"),
                            SuccessRequests = GetInt(dict, "success_requests"),
                            ErrorRequests = GetInt(dict, "error_requests")
                        });
                    }
                }
            }
            return new UsageHistoryResult
            {
                ApiKeyId = GetString(data, "api_key_id"),
                Days = days
            };
        }

        private UsageByToolResult ParseUsageByToolResult(Dictionary<string, object> data)
        {
            return new UsageByToolResult
            {
                Date = GetString(data, "date"),
                Tools = GetIntDict(data, "tools"),
                Endpoints = GetIntDict(data, "endpoints")
            };
        }

        private UsageMonthlyResult ParseUsageMonthlyResult(Dictionary<string, object> data)
        {
            return new UsageMonthlyResult
            {
                Tier = GetString(data, "tier"),
                TierDisplayName = GetString(data, "tier_display_name"),
                Billing = GetDict(data, "billing"),
                UsageInfo = GetDict(data, "usage"),
                RateLimit = GetDict(data, "rate_limit"),
                Recommendations = GetDict(data, "recommendations"),
                Links = GetDict(data, "links")
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

        private static int GetInt(Dictionary<string, object> data, string key)
        {
            if (data.TryGetValue(key, out var value))
            {
                if (value is long l) return (int)l;
                if (value is int i) return i;
                if (value is double d) return (int)d;
                if (int.TryParse(value?.ToString(), out var parsed)) return parsed;
            }
            return 0;
        }

        private static double GetDouble(Dictionary<string, object> data, string key)
        {
            if (data.TryGetValue(key, out var value))
            {
                if (value is double d) return d;
                if (value is float f) return f;
                if (value is long l) return l;
                if (double.TryParse(value?.ToString(), out var parsed)) return parsed;
            }
            return 0.0;
        }

        private static int? GetNullableInt(Dictionary<string, object> data, string key)
        {
            if (data.TryGetValue(key, out var value) && value != null)
            {
                if (value is int i) return i;
                if (value is long l) return (int)l;
                if (value is double d) return (int)d;
                if (int.TryParse(value.ToString(), out var parsed)) return parsed;
            }
            return null;
        }

        private static double? GetNullableDouble(Dictionary<string, object> data, string key)
        {
            if (data.TryGetValue(key, out var value) && value != null)
            {
                if (value is double d) return d;
                if (value is float f) return f;
                if (value is long l) return l;
                if (double.TryParse(value.ToString(), out var parsed)) return parsed;
            }
            return null;
        }

        private static bool? GetNullableBool(Dictionary<string, object> data, string key)
        {
            if (data.TryGetValue(key, out var value) && value != null)
            {
                if (value is bool b) return b;
                if (bool.TryParse(value.ToString(), out var parsed)) return parsed;
            }
            return null;
        }

        private static Dictionary<string, int> GetIntDict(Dictionary<string, object> data, string key)
        {
            var result = new Dictionary<string, int>();
            if (data.TryGetValue(key, out var value) && value is Dictionary<string, object> dict)
            {
                foreach (var kvp in dict)
                {
                    if (kvp.Value is long l) result[kvp.Key] = (int)l;
                    else if (kvp.Value is int i) result[kvp.Key] = i;
                    else if (kvp.Value is double d) result[kvp.Key] = (int)d;
                    else if (int.TryParse(kvp.Value?.ToString(), out var parsed)) result[kvp.Key] = parsed;
                }
            }
            return result;
        }

        [Serializable]
        private class JsonWrapper
        {
            public Dictionary<string, object> data;
        }
    }
}
