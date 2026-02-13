using System;
using System.Collections.Generic;
using NUnit.Framework;

namespace Tuteliq.Tests
{
    public class TuteliqClientTests
    {
        [Test]
        public void Constructor_ValidApiKey_CreatesClient()
        {
            var client = new TuteliqClient("test-api-key-12345");
            Assert.IsNotNull(client);
        }

        [Test]
        public void Constructor_EmptyApiKey_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => new TuteliqClient(""));
        }

        [Test]
        public void Constructor_ShortApiKey_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => new TuteliqClient("short"));
        }

        [Test]
        public void Constructor_WithOptions_CreatesClient()
        {
            var client = new TuteliqClient(
                apiKey: "test-api-key-12345",
                timeout: 60f,
                maxRetries: 5,
                retryDelay: 2f
            );
            Assert.IsNotNull(client);
        }
    }

    public class EnumTests
    {
        [Test]
        public void Severity_ToApiString_ReturnsLowercase()
        {
            Assert.AreEqual("low", Severity.Low.ToApiString());
            Assert.AreEqual("medium", Severity.Medium.ToApiString());
            Assert.AreEqual("high", Severity.High.ToApiString());
            Assert.AreEqual("critical", Severity.Critical.ToApiString());
        }

        [Test]
        public void ParseSeverity_ValidString_ReturnsEnum()
        {
            Assert.AreEqual(Severity.Low, EnumExtensions.ParseSeverity("low"));
            Assert.AreEqual(Severity.Critical, EnumExtensions.ParseSeverity("critical"));
        }

        [Test]
        public void ParseSeverity_InvalidString_ReturnsDefault()
        {
            Assert.AreEqual(Severity.Low, EnumExtensions.ParseSeverity("unknown"));
        }

        [Test]
        public void GroomingRisk_ToApiString_ReturnsLowercase()
        {
            Assert.AreEqual("none", GroomingRisk.None.ToApiString());
            Assert.AreEqual("high", GroomingRisk.High.ToApiString());
        }

        [Test]
        public void RiskLevel_ToApiString_ReturnsLowercase()
        {
            Assert.AreEqual("safe", RiskLevel.Safe.ToApiString());
            Assert.AreEqual("critical", RiskLevel.Critical.ToApiString());
        }

        [Test]
        public void EmotionTrend_ToApiString_ReturnsLowercase()
        {
            Assert.AreEqual("improving", EmotionTrend.Improving.ToApiString());
            Assert.AreEqual("stable", EmotionTrend.Stable.ToApiString());
            Assert.AreEqual("worsening", EmotionTrend.Worsening.ToApiString());
        }

        [Test]
        public void Audience_ToApiString_ReturnsLowercase()
        {
            Assert.AreEqual("child", Audience.Child.ToApiString());
            Assert.AreEqual("parent", Audience.Parent.ToApiString());
        }

        [Test]
        public void MessageRole_ToApiString_ReturnsLowercase()
        {
            Assert.AreEqual("adult", MessageRole.Adult.ToApiString());
            Assert.AreEqual("child", MessageRole.Child.ToApiString());
        }
    }

    public class ModelTests
    {
        [Test]
        public void AnalysisContext_CanCreate()
        {
            var context = new AnalysisContext
            {
                Language = "en",
                AgeGroup = "11-13",
                Relationship = "classmates",
                Platform = "chat"
            };

            Assert.AreEqual("en", context.Language);
            Assert.AreEqual("11-13", context.AgeGroup);
        }

        [Test]
        public void GroomingMessage_CanCreate()
        {
            var msg = new GroomingMessage(MessageRole.Adult, "Hello");

            Assert.AreEqual(MessageRole.Adult, msg.Role);
            Assert.AreEqual("Hello", msg.Content);
        }

        [Test]
        public void DetectGroomingInput_CanCreate()
        {
            var input = new DetectGroomingInput
            {
                Messages = new List<GroomingMessage>
                {
                    new GroomingMessage(MessageRole.Adult, "Hello"),
                    new GroomingMessage(MessageRole.Child, "Hi")
                },
                ChildAge = 12
            };

            Assert.AreEqual(2, input.Messages.Count);
            Assert.AreEqual(12, input.ChildAge);
        }

        [Test]
        public void EmotionMessage_CanCreate()
        {
            var msg = new EmotionMessage("user", "I feel happy");

            Assert.AreEqual("user", msg.Sender);
            Assert.AreEqual("I feel happy", msg.Content);
        }

        [Test]
        public void GetActionPlanInput_CanCreate()
        {
            var input = new GetActionPlanInput
            {
                Situation = "Someone is spreading rumors",
                ChildAge = 12,
                Audience = Audience.Child,
                Severity = Severity.Medium
            };

            Assert.AreEqual("Someone is spreading rumors", input.Situation);
            Assert.AreEqual(12, input.ChildAge);
            Assert.AreEqual(Audience.Child, input.Audience);
            Assert.AreEqual(Severity.Medium, input.Severity);
        }

        [Test]
        public void ReportMessage_CanCreate()
        {
            var msg = new ReportMessage("user1", "Bad message");

            Assert.AreEqual("user1", msg.Sender);
            Assert.AreEqual("Bad message", msg.Content);
        }
    }

    public class ErrorTests
    {
        [Test]
        public void TuteliqException_HasMessage()
        {
            var error = new TuteliqException("Test error");
            Assert.AreEqual("Test error", error.Message);
        }

        [Test]
        public void TuteliqException_HasDetails()
        {
            var details = new { code = 123 };
            var error = new TuteliqException("Test error", details);
            Assert.AreEqual(details, error.Details);
        }

        [Test]
        public void ServerException_HasStatusCode()
        {
            var error = new ServerException("Server error", 500);
            Assert.AreEqual("Server error", error.Message);
            Assert.AreEqual(500, error.StatusCode);
        }
    }
}
